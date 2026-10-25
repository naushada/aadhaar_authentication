#include "uidai/core/error.h"
#include "uidai/transport/chunked.h"
#include "uidai/transport/event_loop.h"
#include "uidai/transport/http.h"
#include "uidai/transport/transport.h"

#include "test_util.h"

#include <event2/event.h>

#include <string>
#include <string_view>

using namespace uidai::transport;

namespace {

void feedByteByByte(ChunkedDecoder& d, std::string_view s) {
  for (char c : s) d.feed(std::string_view(&c, 1));
}

} // namespace

TEST(chunked_single_chunk) {
  auto body = decodeChunked("B\r\nhello world\r\n0\r\n\r\n");
  CHECK_EQ(body, std::string("hello world"));
}

TEST(chunked_multiple_chunks) {
  auto body = decodeChunked("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
  CHECK_EQ(body, std::string("Wikipedia"));
}

TEST(chunked_with_extension) {
  auto body = decodeChunked("4;name=value\r\nWiki\r\n0\r\n\r\n");
  CHECK_EQ(body, std::string("Wiki"));
}

TEST(chunked_incremental_and_complete) {
  ChunkedDecoder d;
  feedByteByByte(d, "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
  CHECK(d.complete());
  CHECK(!d.error());
  CHECK_EQ(d.body(), std::string("Wikipedia"));
}

TEST(chunked_incomplete) {
  ChunkedDecoder d;
  d.feed("4\r\nWi");
  CHECK(!d.complete());
  CHECK(!d.error());
  CHECK_EQ(d.body(), std::string("Wi"));
}

TEST(chunked_missing_terminal_throws) {
  bool threw = false;
  try {
    decodeChunked("4\r\nWiki\r\n5\r\npedia\r\n");
  } catch (const uidai::UidaiError&) {
    threw = true;
  }
  CHECK(threw);
}

TEST(request_serialize_matches_uidai_wire_format) {
  HttpRequest req;
  req.method = "POST";
  req.target = "http://developer.uidai.gov.in/auth/2.0/public/9/8/license-key";
  req.headers = {
      {"Host", "developer.uidai.gov.in"},
      {"Content-Type", "text/xml"},
      {"Connection", "Keep-alive"},
      {"Content-Length", "345"},
  };
  req.body = "<signed-xml/>";

  const std::string expected =
      "POST http://developer.uidai.gov.in/auth/2.0/public/9/8/license-key HTTP/1.1\r\n"
      "Host: developer.uidai.gov.in\r\n"
      "Content-Type: text/xml\r\n"
      "Connection: Keep-alive\r\n"
      "Content-Length: 345\r\n"
      "\r\n"
      "<signed-xml/>";

  CHECK_EQ(req.serialize(), expected);
}

TEST(parse_http_response_chunked) {
  const std::string raw =
      "HTTP/1.1 200 OK\r\n"
      "Transfer-Encoding: chunked\r\n"
      "\r\n"
      "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";

  HttpResponse r = parseHttpResponse(raw);
  CHECK_EQ(r.status, 200);
  CHECK_EQ(r.reason, std::string("OK"));
  CHECK_EQ(r.version, std::string("HTTP/1.1"));
  CHECK_EQ(r.body, std::string("Wikipedia"));
  CHECK(r.header("transfer-encoding").has_value());
  CHECK_EQ(*r.header("Transfer-Encoding"), std::string("chunked"));
}

TEST(parse_http_response_content_length) {
  const std::string raw =
      "HTTP/1.1 200 OK\r\n"
      "Content-Length: 5\r\n"
      "\r\n"
      "hello";

  HttpResponse r = parseHttpResponse(raw);
  CHECK_EQ(r.status, 200);
  CHECK_EQ(r.body, std::string("hello"));
  CHECK_EQ(*r.header("content-length"), std::string("5"));
}

TEST(http_response_complete_detection) {
  const std::string cl = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
  CHECK(httpResponseComplete(cl));
  CHECK(!httpResponseComplete(cl.substr(0, cl.size() - 1)));

  const std::string chunked =
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
      "4\r\nWiki\r\n0\r\n\r\n";
  CHECK(httpResponseComplete(chunked));
  CHECK(!httpResponseComplete(chunked.substr(0, chunked.size() - 3)));

  CHECK(!httpResponseComplete("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"));
}

TEST(event_loop_dispatch_and_stop) {
  EventLoop loop;
  CHECK(loop.base() != nullptr);

  bool fired = false;
  struct Cb {
    bool* fired;
    EventLoop* loop;
  } cb{&fired, &loop};

  struct event* ev = event_new(
      loop.base(), -1, EV_TIMEOUT,
      [](evutil_socket_t, short, void* arg) {
        auto* c = static_cast<Cb*>(arg);
        *c->fired = true;
        c->loop->stop();
      },
      &cb);
  CHECK(ev != nullptr);

  struct timeval tv { 0, 1000 };
  event_add(ev, &tv);
  loop.run();
  CHECK(fired);
  event_free(ev);
}
