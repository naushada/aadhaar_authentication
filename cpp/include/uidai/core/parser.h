#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace uidai::core {

// Splits a "&"-separated query string (the part after any leading '?' of a
// GUI request line) and returns the value for `name`, or nullopt when absent.
// Ports uidai_get_param.
class QueryParser {
public:
  explicit QueryParser(std::string_view line);

  std::optional<std::string> param(std::string_view name) const;

private:
  std::string query_;
};

// Splits a "{k=v,k=v,…}" attribute block and returns the value for `name`, or
// nullopt when absent. A present-but-empty value ("k=") yields an empty string.
// Ports uidai_get_attr.
class AttrParser {
public:
  explicit AttrParser(std::string_view block);

  std::optional<std::string> attr(std::string_view name) const;

private:
  std::string content_;
};

} // namespace uidai::core
