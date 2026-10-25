#pragma once

#include "uidai/transport/event_loop.h"

#include <functional>
#include <memory>
#include <string_view>

namespace uidai::transport {

// A libevent line source over the GUI child's stdout pipe, with a sink for
// writing response lines back to the child's stdin. Registered as an
// EV_READ | EV_PERSIST event on the owning EventLoop; each complete newline-
// terminated line is handed to the LineHandler. A line equal to "Exit" echoes
// "exit\n" to the child and breaks the loop. Ports uidai_process_gui_req.
class GuiPipe {
public:
  using LineHandler = std::function<void(std::string_view line)>;

  GuiPipe(EventLoop& loop, int readFd, int writeFd, LineHandler onLine);
  ~GuiPipe();

  GuiPipe(const GuiPipe&) = delete;
  GuiPipe& operator=(const GuiPipe&) = delete;

  // Write a full command line to the GUI (callers include the trailing '\n').
  void send(std::string_view line);

private:
  static void onReadable(int fd, short what, void* arg);

  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace uidai::transport
