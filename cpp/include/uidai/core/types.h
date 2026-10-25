#pragma once

#include <string_view>

namespace uidai {

// Protocol versions dispatched on in staging/uidai.c.
enum class Version { V16, V20, V21, V25, Unknown };

// Top-level request families.
enum class RequestKind { Otp, Auth, Ekyc };

inline Version versionFromString(std::string_view s) {
  if (s == "1.6") return Version::V16;
  if (s == "2.0") return Version::V20;
  if (s == "2.1") return Version::V21;
  if (s == "2.5") return Version::V25;
  return Version::Unknown;
}

inline constexpr std::string_view versionToString(Version v) {
  switch (v) {
    case Version::V16: return "1.6";
    case Version::V20: return "2.0";
    case Version::V21: return "2.1";
    case Version::V25: return "2.5";
    default:           return "?";
  }
}

} // namespace uidai
