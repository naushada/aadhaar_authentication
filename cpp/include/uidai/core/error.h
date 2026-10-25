#pragma once

#include <stdexcept>
#include <string>
#include <utility>

namespace uidai {

// Thrown wherever the C code assert()ed or returned a bare <0. Carries the
// context that assert() used to drop on the floor.
class UidaiError : public std::runtime_error {
public:
  explicit UidaiError(std::string msg) : std::runtime_error(std::move(msg)) {}
};

} // namespace uidai
