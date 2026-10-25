#include "uidai/core/response_parser.h"

#include <cstddef>

namespace uidai::core {

namespace {

// Return the value of the XML attribute `name="…"` inside an element's opening
// tag. The attribute name must be a full token (preceded by whitespace or '<'),
// so a `name` occurring inside another attribute's value is not matched.
std::string xmlAttr(std::string_view tag, std::string_view name) {
  const std::string needle = std::string(name) + "=\"";
  std::size_t pos = 0;
  while (true) {
    const std::size_t at = tag.find(needle, pos);
    if (at == std::string_view::npos) return {};
    bool boundary = (at == 0);
    if (!boundary) {
      const char c = tag[at - 1];
      boundary = (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '<');
    }
    if (boundary) {
      const std::size_t value = at + needle.size();
      const std::size_t close = tag.find('"', value);
      if (close != std::string_view::npos) {
        return std::string(tag.substr(value, close - value));
      }
      return {};
    }
    pos = at + 1;
  }
}

} // namespace

Response parseResponseXml(std::string_view body) {
  // Skip a leading "<?xml …?>" declaration.
  std::size_t start = 0;
  if (body.size() >= 5 && body.substr(0, 5) == "<?xml") {
    const std::size_t declEnd = body.find("?>");
    if (declEnd != std::string_view::npos) start = declEnd + 2;
  }

  const std::size_t lt = body.find('<', start);
  if (lt == std::string_view::npos) return {};
  const std::size_t gt = body.find('>', lt + 1);
  if (gt == std::string_view::npos) return {};

  const std::string_view tag = body.substr(lt + 1, gt - lt - 1);

  Response r;
  r.ret = xmlAttr(tag, "ret");
  r.err = xmlAttr(tag, "err");
  r.code = xmlAttr(tag, "code");
  r.actn = xmlAttr(tag, "actn");
  r.info = xmlAttr(tag, "info");
  return r;
}

std::string formatDisplayResponse(const Response& r) {
  std::string out = "response_display_response ";
  if (r.ok()) {
    out += r.ret;
    out += " \"\" ";  // err
    out += r.code;
    out += " \"\" ";  // actn
    out += r.info;
  } else {
    out += r.ret;
    out += " ";
    out += r.err;
    out += " ";
    out += r.code;
    out += " ";
    out += r.actn;
    out += " ";
    out += r.info;
  }
  out += "\n";
  return out;
}

} // namespace uidai::core
