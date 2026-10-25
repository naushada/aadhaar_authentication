#include "uidai/transport/http.h"

#include "uidai/core/error.h"
#include "uidai/transport/chunked.h"

#include <cctype>
#include <cstdlib>

namespace uidai::transport {

namespace {

std::string_view trim(std::string_view s) {
  const std::size_t b = s.find_first_not_of(" \t");
  if (b == std::string_view::npos) return {};
  const std::size_t e = s.find_last_not_of(" \t");
  return s.substr(b, e - b + 1);
}

bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) !=
        std::tolower(static_cast<unsigned char>(b[i]))) return false;
  }
  return true;
}

bool icontains(std::string_view hay, std::string_view needle) {
  if (needle.empty()) return true;
  if (needle.size() > hay.size()) return false;
  for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
    if (iequals(hay.substr(i, needle.size()), needle)) return true;
  }
  return false;
}

int toInt(std::string_view s) {
  return static_cast<int>(std::strtol(std::string(s).c_str(), nullptr, 10));
}

// Split raw into the header block and the body. Returns false while the header
// terminator is still absent (the transport keeps reading).
bool splitHeadBody(std::string_view raw, std::string_view& head,
                   std::string_view& body) {
  const std::size_t sep = raw.find("\r\n\r\n");
  if (sep != std::string_view::npos) {
    head = raw.substr(0, sep);
    body = raw.substr(sep + 4);
    return true;
  }
  const std::size_t lf = raw.find("\n\n");
  if (lf != std::string_view::npos) {
    head = raw.substr(0, lf);
    body = raw.substr(lf + 2);
    return true;
  }
  return false;
}

} // namespace

std::string HttpRequest::serialize() const {
  std::string out;
  out.reserve(target.size() + body.size() + headers.size() * 32 + 32);
  out += method;
  out += ' ';
  out += target;
  out += ' ';
  out += version;
  out += "\r\n";
  for (const auto& h : headers) {
    out += h.first;
    out += ": ";
    out += h.second;
    out += "\r\n";
  }
  out += "\r\n";
  out += body;
  return out;
}

std::optional<std::string> HttpResponse::header(const std::string& name) const {
  for (const auto& h : headers) {
    if (iequals(h.first, name)) return h.second;
  }
  return std::nullopt;
}

HttpResponse parseHttpResponse(std::string_view raw) {
  std::string_view head, body;
  if (!splitHeadBody(raw, head, body)) {
    throw UidaiError("malformed HTTP response: missing header terminator");
  }

  HttpResponse r;

  // Status line: "HTTP/1.1 200 OK".
  const std::size_t lineEnd = head.find("\r\n");
  std::string_view sl =
      (lineEnd == std::string_view::npos) ? head : head.substr(0, lineEnd);
  const std::size_t sp1 = sl.find(' ');
  if (sp1 == std::string_view::npos) throw UidaiError("malformed status line");
  r.version.assign(sl.substr(0, sp1));
  sl.remove_prefix(sp1 + 1);
  while (!sl.empty() && (sl.front() == ' ' || sl.front() == '\t')) {
    sl.remove_prefix(1);
  }
  const std::size_t sp2 = sl.find(' ');
  const std::string_view statusStr =
      (sp2 == std::string_view::npos) ? sl : sl.substr(0, sp2);
  r.status = toInt(statusStr);
  r.reason = (sp2 == std::string_view::npos) ? std::string()
                                             : std::string(trim(sl.substr(sp2 + 1)));

  // Headers.
  std::size_t pos = (lineEnd == std::string_view::npos) ? head.size() : lineEnd + 2;
  while (pos < head.size()) {
    const std::size_t e = head.find("\r\n", pos);
    const std::string_view line =
        head.substr(pos, (e == std::string_view::npos ? head.size() : e) - pos);
    const std::size_t colon = line.find(':');
    if (colon != std::string_view::npos) {
      r.headers.emplace_back(std::string(line.substr(0, colon)),
                             std::string(trim(line.substr(colon + 1))));
    }
    if (e == std::string_view::npos) break;
    pos = e + 2;
  }

  r.body.assign(body);

  auto te = r.header("Transfer-Encoding");
  if (te && icontains(*te, "chunked")) {
    r.body = decodeChunked(r.body);
  } else {
    auto cl = r.header("Content-Length");
    if (cl) {
      const long n = std::strtol(cl->c_str(), nullptr, 10);
      if (n >= 0 && static_cast<std::size_t>(n) < r.body.size()) {
        r.body.resize(static_cast<std::size_t>(n));
      }
    }
  }

  return r;
}

bool httpResponseComplete(std::string_view raw) {
  std::string_view head, body;
  if (!splitHeadBody(raw, head, body)) return false;

  bool chunked = false;
  bool hasCl = false;
  std::size_t cl = 0;

  std::size_t pos = head.find("\r\n");
  if (pos != std::string_view::npos) pos += 2;
  while (pos < head.size()) {
    const std::size_t e = head.find("\r\n", pos);
    const std::string_view line =
        head.substr(pos, (e == std::string_view::npos ? head.size() : e) - pos);
    const std::size_t colon = line.find(':');
    if (colon != std::string_view::npos) {
      const std::string_view name = line.substr(0, colon);
      const std::string_view value = trim(line.substr(colon + 1));
      if (iequals(name, "transfer-encoding") && icontains(value, "chunked")) {
        chunked = true;
      } else if (iequals(name, "content-length")) {
        hasCl = true;
        cl = static_cast<std::size_t>(std::strtoul(std::string(value).c_str(), nullptr, 10));
      }
    }
    if (e == std::string_view::npos) break;
    pos = e + 2;
  }

  if (chunked) {
    // Terminal zero-chunk plus final CRLF.
    return body.size() >= 5 && body.compare(body.size() - 5, 5, "0\r\n\r\n") == 0;
  }
  if (hasCl) return body.size() >= cl;
  return false; // connection-close delimited: complete only on EOF
}

} // namespace uidai::transport
