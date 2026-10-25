#pragma once

#include <string_view>

namespace uidai {

enum class LogLevel { Debug, Info, Warn, Error };

// Minimal single-threaded logger to stderr. Mirrors the bare fprintf(stderr, …)
// logging in the C sources without their varargs/format-string hazards.
class Logger {
public:
  static Logger& instance();

  void setLevel(LogLevel level) noexcept;
  LogLevel level() const noexcept;

  void log(LogLevel lvl, std::string_view msg) const;

  static void debug(std::string_view msg);
  static void info(std::string_view msg);
  static void warn(std::string_view msg);
  static void error(std::string_view msg);

private:
  Logger() = default;
  LogLevel level_ = LogLevel::Info;
};

} // namespace uidai
