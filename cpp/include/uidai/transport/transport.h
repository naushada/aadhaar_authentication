#pragma once

#include "uidai/transport/http.h"

#include <cstdint>
#include <memory>
#include <string>

namespace uidai::transport {

// M0 smoke symbol: returns LIBEVENT_VERSION_NUMBER (e.g. 0x02010d01).
uint32_t libeventVersionNumber();

// A blocking, single-request HTTP client over a UIDAI endpoint. The strategy
// objects (OTP/Auth/eKYC) program against this interface so the socket layer
// can be swapped without touching protocol code.
class HttpTransport {
public:
  virtual ~HttpTransport() = default;
  virtual HttpResponse perform(const HttpRequest& req, int timeoutMs = 5000) = 0;
};

// libevent bufferevent implementation. Reproduces uidai_connect_uidai /
// uidai_send / uidai_recv / uidai_chunked_rsp using a non-blocking socket and
// bufferevent rather than gethostbyname + blocking send/recv + select. When
// `useTls` is true, the socket is wrapped in an OpenSSL bufferevent
// (bufferevent_openssl_socket_new) so the request goes out over HTTPS with the
// peer certificate verified against the system CA store.
class LibeventTransport : public HttpTransport {
public:
  LibeventTransport(std::string host, unsigned short port, bool useTls = false);
  ~LibeventTransport() override;

  LibeventTransport(const LibeventTransport&) = delete;
  LibeventTransport& operator=(const LibeventTransport&) = delete;

  HttpResponse perform(const HttpRequest& req, int timeoutMs = 5000) override;

private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace uidai::transport
