#include "uidai/transport/transport.h"

#include "uidai/core/error.h"
#include "uidai/transport/event_loop.h"

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <utility>

namespace uidai::transport {

uint32_t libeventVersionNumber() {
  return static_cast<uint32_t>(LIBEVENT_VERSION_NUMBER);
}

struct LibeventTransport::Impl {
  std::string host;
  unsigned short port;
};

LibeventTransport::LibeventTransport(std::string host, unsigned short port)
    : impl_(std::make_unique<Impl>()) {
  impl_->host = std::move(host);
  impl_->port = port;
}

LibeventTransport::~LibeventTransport() = default;

namespace {

struct ConnState {
  event_base* base = nullptr;
  std::string wire; // serialized request
  std::string raw;  // accumulated response bytes
  bool done = false;
  bool failed = false;
  std::string err;
};

void onRead(struct bufferevent* bev, void* arg) {
  auto* st = static_cast<ConnState*>(arg);
  char buf[4096];
  std::size_t n;
  while ((n = bufferevent_read(bev, buf, sizeof(buf))) > 0) {
    st->raw.append(buf, n);
  }
  if (httpResponseComplete(st->raw)) {
    st->done = true;
    event_base_loopexit(st->base, nullptr);
  }
}

void onEvent(struct bufferevent* bev, short what, void* arg) {
  auto* st = static_cast<ConnState*>(arg);
  if (what & BEV_EVENT_CONNECTED) {
    if (bufferevent_write(bev, st->wire.data(), st->wire.size()) < 0) {
      st->failed = true;
      st->err = "bufferevent_write failed";
      event_base_loopexit(st->base, nullptr);
    }
  } else if (what & BEV_EVENT_ERROR) {
    st->failed = true;
    st->err = "connection error";
    event_base_loopexit(st->base, nullptr);
  } else if (what & BEV_EVENT_EOF) {
    // Connection closed. For connection-close-delimited responses this is the
    // completion signal; for length/chunked responses we already loopexited.
    st->done = true;
    event_base_loopexit(st->base, nullptr);
  }
}

void onTimeout(evutil_socket_t, short, void* arg) {
  auto* st = static_cast<ConnState*>(arg);
  st->failed = true;
  st->err = "timeout";
  event_base_loopexit(st->base, nullptr);
}

sockaddr_in resolveIpv4(const std::string& host, unsigned short port) {
  struct addrinfo hints {};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  struct addrinfo* res = nullptr;
  const int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res);
  if (rc != 0 || !res) {
    throw UidaiError("getaddrinfo failed for " + host);
  }
  sockaddr_in sin {};
  std::memcpy(&sin, res->ai_addr, res->ai_addrlen);
  sin.sin_port = htons(port);
  freeaddrinfo(res);
  return sin;
}

// Capture the raw HTTP request/response to <UIDAI_DUMP_DIR>/<name><seq>.http
// when the UIDAI_DUMP_DIR environment variable is set. Keeps a byte-exact
// record of what was sent and received for offline reference; no-op otherwise.
void dumpHttpCapture(const std::string& name, const std::string& data) {
  const char* dir = std::getenv("UIDAI_DUMP_DIR");
  if (!dir || !*dir || data.empty()) return;
  static std::atomic<int> seq{0};
  const int n = seq.fetch_add(1);
  std::string path(dir);
  if (!path.empty() && path.back() != '/') path += '/';
  path += name;
  path += std::to_string(n);
  path += ".http";
  std::ofstream out(path, std::ios::binary);
  if (out) out.write(data.data(), static_cast<std::streamsize>(data.size()));
}

} // namespace

HttpResponse LibeventTransport::perform(const HttpRequest& req, int timeoutMs) {
  ConnState st;
  st.wire = req.serialize();
  dumpHttpCapture("request_", st.wire);

  EventLoop loop;
  st.base = loop.base();

  struct bufferevent* bev =
      bufferevent_socket_new(loop.base(), -1, BEV_OPT_CLOSE_ON_FREE);
  if (!bev) throw UidaiError("bufferevent_socket_new failed");
  bufferevent_setcb(bev, onRead, nullptr, onEvent, &st);

  sockaddr_in sin = resolveIpv4(impl_->host, impl_->port);
  if (bufferevent_socket_connect(bev, reinterpret_cast<sockaddr*>(&sin),
                                 sizeof(sin)) < 0) {
    bufferevent_free(bev);
    throw UidaiError("bufferevent_socket_connect failed for " + impl_->host);
  }
  bufferevent_enable(bev, EV_READ | EV_WRITE);

  struct event* tev = event_new(loop.base(), -1, EV_TIMEOUT, onTimeout, &st);
  if (!tev) {
    bufferevent_free(bev);
    throw UidaiError("event_new failed");
  }
  struct timeval tv;
  tv.tv_sec = timeoutMs / 1000;
  tv.tv_usec = (timeoutMs % 1000) * 1000;
  event_add(tev, &tv);

  loop.run();
  dumpHttpCapture("response_", st.raw);

  event_free(tev);
  bufferevent_free(bev);

  if (st.failed) throw UidaiError("transport: " + st.err);
  if (!st.done) throw UidaiError("transport: loop exited without a response");
  return parseHttpResponse(st.raw);
}

} // namespace uidai::transport
