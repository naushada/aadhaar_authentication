#include "uidai/core/logger.h"

#include <cstdio>
#include <ctime>

namespace uidai {

Logger& Logger::instance() {
  static Logger l;
  return l;
}

void Logger::setLevel(LogLevel level) noexcept { level_ = level; }
LogLevel Logger::level() const noexcept { return level_; }

static const char* levelTag(LogLevel lvl) {
  switch (lvl) {
    case LogLevel::Debug: return "DEBUG";
    case LogLevel::Info:  return "INFO";
    case LogLevel::Warn:  return "WARN";
    case LogLevel::Error: return "ERROR";
  }
  return "?";
}

void Logger::log(LogLevel lvl, std::string_view msg) const {
  if (static_cast<int>(lvl) < static_cast<int>(level_)) return;

  std::time_t t = std::time(nullptr);
  std::tm tm{};
#if defined(_WIN32)
  localtime_s(&tm, &t);
#else
  localtime_r(&t, &tm);
#endif
  char ts[24];
  std::strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);
  std::fprintf(stderr, "%s [%s] %.*s\n", ts, levelTag(lvl),
               static_cast<int>(msg.size()), msg.data());
}

void Logger::debug(std::string_view msg) { instance().log(LogLevel::Debug, msg); }
void Logger::info(std::string_view msg)  { instance().log(LogLevel::Info, msg); }
void Logger::warn(std::string_view msg)  { instance().log(LogLevel::Warn, msg); }
void Logger::error(std::string_view msg) { instance().log(LogLevel::Error, msg); }

} // namespace uidai
