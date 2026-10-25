#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace uidai::transport {

using Header = std::pair<std::string, std::string>;

// An outbound HTTP/1.1 request. serialize() reproduces the exact wire format of
// uidai's C client (otp_compose_http_request): method, absolute-URI target,
// version, then ordered "Name: value\r\n" headers, a blank line, then the body.
struct HttpRequest {
  std::string method = "POST";
  std::string target;   // full request-target (UIDAI uses an absolute URI)
  std::string version = "HTTP/1.1";
  std::vector<Header> headers;
  std::string body;

  std::string serialize() const;
};

// A received HTTP/1.1 response with any chunked transfer-encoding already
// decoded into `body`.
struct HttpResponse {
  std::string version;
  int status = 0;
  std::string reason;
  std::vector<Header> headers;
  std::string body;

  // Case-insensitive header lookup.
  std::optional<std::string> header(const std::string& name) const;
};

// Parse a complete raw HTTP/1.1 response (status line + headers + body),
// de-chunking the body when "Transfer-Encoding: chunked" is present and
// honouring Content-Length otherwise. Throws uidai::UidaiError on malformed
// input.
HttpResponse parseHttpResponse(std::string_view raw);

// True when `raw` holds a complete HTTP/1.1 response: headers terminated, and
// the body fully present per Content-Length or the chunked zero-chunk
// terminator. Used by the transport read callback to know when to stop.
bool httpResponseComplete(std::string_view raw);

} // namespace uidai::transport
