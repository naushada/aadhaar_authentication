#include "uidai/transport/gui_pipe.h"

#include "uidai/core/error.h"

#include <event2/event.h>
#include <event2/util.h>

#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <utility>

namespace uidai::transport {

struct GuiPipe::Impl {
  event_base* base = nullptr;
  int readFd = -1;
  int writeFd = -1;
  LineHandler onLine;
  struct event* ev = nullptr;
  std::string pending;
};

namespace {

void writeAll(int fd, std::string_view data) {
  std::size_t off = 0;
  while (off < data.size()) {
    const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      break;
    }
    off += static_cast<std::size_t>(n);
  }
}

} // namespace

void GuiPipe::onReadable(int fd, short, void* arg) {
  auto* impl = static_cast<GuiPipe::Impl*>(arg);

  bool eof = false;
  char buf[4096];
  for (;;) {
    const ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n > 0) {
      impl->pending.append(buf, static_cast<std::size_t>(n));
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else if (n == 0) {
      eof = true; // child closed its stdout
      break;
    } else {
      break; // EAGAIN (no more data)
    }
  }

  std::size_t pos;
  while ((pos = impl->pending.find('\n')) != std::string::npos) {
    std::string line = impl->pending.substr(0, pos);
    impl->pending.erase(0, pos + 1);
    if (!line.empty() && line.back() == '\r') line.pop_back();

    if (line == "Exit") {
      ::write(impl->writeFd, "exit\n", 5);
      event_del(impl->ev);
      event_base_loopexit(impl->base, nullptr);
      break;
    }
    if (impl->onLine) impl->onLine(std::move(line));
  }

  if (eof) {
    event_del(impl->ev);
    event_base_loopexit(impl->base, nullptr);
  }
}

GuiPipe::GuiPipe(EventLoop& loop, int readFd, int writeFd, LineHandler onLine)
    : impl_(std::make_unique<Impl>()) {
  impl_->base = loop.base();
  impl_->readFd = readFd;
  impl_->writeFd = writeFd;
  impl_->onLine = std::move(onLine);

  evutil_make_socket_nonblocking(readFd);

  impl_->ev = event_new(loop.base(), readFd, EV_READ | EV_PERSIST,
                        &GuiPipe::onReadable, impl_.get());
  if (!impl_->ev) throw UidaiError("event_new failed for gui pipe");
  if (event_add(impl_->ev, nullptr) < 0) throw UidaiError("event_add failed");
}

GuiPipe::~GuiPipe() {
  if (impl_->ev) event_free(impl_->ev);
}

void GuiPipe::send(std::string_view line) { writeAll(impl_->writeFd, line); }

} // namespace uidai::transport
