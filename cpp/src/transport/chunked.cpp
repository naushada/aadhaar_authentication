#include "uidai/transport/chunked.h"

#include "uidai/core/error.h"

#include <algorithm>
#include <cstdlib>

namespace uidai::transport {

void ChunkedDecoder::feed(std::string_view in) {
  std::size_t i = 0;
  while (i < in.size()) {
    if (state_ == State::Done || state_ == State::Error) break;
    const char c = in[i];

    switch (state_) {
      case State::Size: {
        line_ += c;
        ++i;
        if (c == '\n') {
          std::string line = line_;
          if (!line.empty() && line.back() == '\n') line.pop_back();
          if (!line.empty() && line.back() == '\r') line.pop_back();
          // Chunk-size may carry a ";"-prefixed extension; ignore it.
          const std::size_t semi = line.find(';');
          if (semi != std::string::npos) line.resize(semi);

          char* end = nullptr;
          const unsigned long sz = std::strtoul(line.c_str(), &end, 16);
          if (end == line.c_str() || *end != '\0') {
            state_ = State::Error;
            break;
          }
          remaining_ = static_cast<std::size_t>(sz);
          line_.clear();
          state_ = (remaining_ == 0) ? State::Trailer : State::Data;
        }
        break;
      }
      case State::Data: {
        const std::size_t take = std::min(remaining_, in.size() - i);
        body_.append(in.data() + i, take);
        remaining_ -= take;
        i += take;
        if (remaining_ == 0) state_ = State::DataCrlf;
        break;
      }
      case State::DataCrlf: {
        if (c == '\r' && crlf_ == 0) {
          crlf_ = 1;
          ++i;
        } else if (c == '\n' && crlf_ == 1) {
          crlf_ = 0;
          state_ = State::Size;
          ++i;
        } else {
          state_ = State::Error;
        }
        break;
      }
      case State::Trailer: {
        line_ += c;
        ++i;
        if (c == '\n') {
          std::string line = line_;
          if (!line.empty() && line.back() == '\n') line.pop_back();
          if (!line.empty() && line.back() == '\r') line.pop_back();
          if (line.empty()) {
            line_.clear();
            state_ = State::Done;
          } else {
            line_.clear(); // ignore trailer header
          }
        }
        break;
      }
      case State::Done:
      case State::Error:
        break;
    }
  }
}

std::string decodeChunked(std::string_view body) {
  ChunkedDecoder d;
  d.feed(body);
  if (d.error()) throw UidaiError("malformed chunked body");
  if (!d.complete()) throw UidaiError("incomplete chunked body");
  return d.takeBody();
}

} // namespace uidai::transport
