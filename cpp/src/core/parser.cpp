#include "uidai/core/parser.h"

#include <cstddef>

namespace uidai::core {

QueryParser::QueryParser(std::string_view line) {
  const std::size_t q = line.find('?');
  query_ = (q == std::string_view::npos) ? std::string(line)
                                         : std::string(line.substr(q + 1));
}

std::optional<std::string> QueryParser::param(std::string_view name) const {
  const std::size_t n = query_.size();
  std::size_t pos = 0;
  while (pos <= n) {
    const std::size_t amp = query_.find('&', pos);
    const std::size_t end = (amp == std::string::npos) ? n : amp;
    const std::string_view seg(query_.data() + pos, end - pos);
    const std::size_t eq = seg.find('=');
    if (eq != std::string_view::npos && seg.substr(0, eq) == name) {
      return std::string(seg.substr(eq + 1));
    }
    if (amp == std::string::npos) break;
    pos = amp + 1;
  }
  return std::nullopt;
}

AttrParser::AttrParser(std::string_view block) {
  const std::size_t a = block.find('{');
  const std::size_t b = block.rfind('}');
  content_ = (a != std::string_view::npos && b != std::string_view::npos &&
              b > a)
                 ? std::string(block.substr(a + 1, b - a - 1))
                 : std::string(block);
}

std::optional<std::string> AttrParser::attr(std::string_view name) const {
  const std::size_t n = content_.size();
  std::size_t pos = 0;
  while (pos <= n) {
    const std::size_t comma = content_.find(',', pos);
    const std::size_t end = (comma == std::string::npos) ? n : comma;
    const std::string_view seg(content_.data() + pos, end - pos);
    const std::size_t eq = seg.find('=');
    if (eq != std::string_view::npos && seg.substr(0, eq) == name) {
      return std::string(seg.substr(eq + 1));
    }
    if (comma == std::string::npos) break;
    pos = comma + 1;
  }
  return std::nullopt;
}

} // namespace uidai::core
