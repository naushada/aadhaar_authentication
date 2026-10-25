#pragma once

struct event_base;

namespace uidai::transport {

// RAII wrapper over libevent's event_base. Owns the base and frees it on
// destruction; move-only so ownership stays unambiguous.
class EventLoop {
public:
  EventLoop();
  ~EventLoop();

  EventLoop(const EventLoop&) = delete;
  EventLoop& operator=(const EventLoop&) = delete;
  EventLoop(EventLoop&&) noexcept;
  EventLoop& operator=(EventLoop&&) noexcept;

  event_base* base() const noexcept;

  // Run the loop until there are no more events or stop() is called.
  void run();

  // Request a graceful exit from run() after the current iteration.
  void stop();

private:
  event_base* base_ = nullptr;
};

} // namespace uidai::transport
