#pragma once

#include <cstddef>
#include <string>
#include <string_view>

namespace uidai::transport {

// Incremental HTTP/1.1 chunked transfer-encoding decoder (RFC 7230 §4.1).
// Reproduces the chunked response handling in uidai_chunked_rsp /
// uidai_pre_process_uidai_rsp, but as a proper state machine instead of a
// hand-rolled strtok_r scan.
class ChunkedDecoder {
public:
  enum class State { Size, Data, DataCrlf, Trailer, Done, Error };

  // Feed bytes; they may arrive in arbitrarily small pieces.
  void feed(std::string_view in);

  bool complete() const noexcept { return state_ == State::Done; }
  bool error() const noexcept { return state_ == State::Error; }
  State state() const noexcept { return state_; }
  const std::string& body() const noexcept { return body_; }
  std::string takeBody() {
    std::string b;
    std::swap(b, body_);
    return b;
  }

private:
  State state_ = State::Size;
  std::string body_;
  std::string line_;
  std::size_t remaining_ = 0;
  int crlf_ = 0; // 0 = expecting '\r', 1 = expecting '\n' after chunk data
};

// Decode a complete chunked body in one shot; throws uidai::UidaiError on
// malformed input or if the body does not terminate with the zero chunk.
std::string decodeChunked(std::string_view body);

} // namespace uidai::transport
