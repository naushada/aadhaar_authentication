#include "uidai/transport/event_loop.h"

#include "uidai/core/error.h"

#include <event2/event.h>

namespace uidai::transport {

EventLoop::EventLoop() {
  base_ = event_base_new();
  if (!base_) throw UidaiError("event_base_new failed");
}

EventLoop::~EventLoop() {
  if (base_) event_base_free(base_);
}

EventLoop::EventLoop(EventLoop&& o) noexcept : base_(o.base_) { o.base_ = nullptr; }

EventLoop& EventLoop::operator=(EventLoop&& o) noexcept {
  if (this != &o) {
    if (base_) event_base_free(base_);
    base_ = o.base_;
    o.base_ = nullptr;
  }
  return *this;
}

event_base* EventLoop::base() const noexcept { return base_; }

void EventLoop::run() {
  if (base_) event_base_dispatch(base_);
}

void EventLoop::stop() {
  if (base_) event_base_loopexit(base_, nullptr);
}

} // namespace uidai::transport
