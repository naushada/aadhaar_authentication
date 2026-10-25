#include "uidai/transport/event_loop.h"
#include "uidai/transport/gui_pipe.h"

#include "test_util.h"

#include <sys/socket.h>
#include <unistd.h>

#include <string>
#include <string_view>
#include <vector>

using namespace uidai::transport;

namespace {

void writeAll(int fd, std::string_view s) {
  size_t off = 0;
  while (off < s.size()) {
    const ssize_t n = ::write(fd, s.data() + off, s.size() - off);
    if (n <= 0) break;
    off += static_cast<size_t>(n);
  }
}

} // namespace

TEST(gui_pipe_reads_single_line) {
  int sv[2];
  CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

  EventLoop loop;
  std::string received;
  GuiPipe pipe(loop, sv[0], sv[1], [&](std::string_view line) {
    received = std::string(line);
    loop.stop();
  });

  writeAll(sv[1], "/request?request=otp\n");
  loop.run();

  CHECK_EQ(received, std::string("/request?request=otp"));
  close(sv[0]);
  close(sv[1]);
}

TEST(gui_pipe_reads_multiple_lines) {
  int sv[2];
  CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

  EventLoop loop;
  std::vector<std::string> lines;
  GuiPipe pipe(loop, sv[0], sv[1], [&](std::string_view line) {
    lines.push_back(std::string(line));
    if (lines.size() == 2) loop.stop();
  });

  writeAll(sv[1], "/a\n/b\n");
  loop.run();

  CHECK_EQ(lines.size(), static_cast<size_t>(2));
  if (lines.size() == 2) {
    CHECK_EQ(lines[0], std::string("/a"));
    CHECK_EQ(lines[1], std::string("/b"));
  }
  close(sv[0]);
  close(sv[1]);
}

TEST(gui_pipe_eof_breaks_loop) {
  int sv[2];
  CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

  EventLoop loop;
  bool handlerCalled = false;
  GuiPipe pipe(loop, sv[0], sv[1], [&](std::string_view) { handlerCalled = true; });

  close(sv[1]); // child's write end closes -> EOF on sv[0]
  loop.run();   // must return instead of busy-looping on the EOF

  CHECK(!handlerCalled);
  close(sv[0]);
}

TEST(gui_pipe_exit_breaks_and_echoes_exit) {
  int sv[2];
  CHECK_EQ(socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);

  int wp[2];
  CHECK_EQ(pipe(wp), 0);

  EventLoop loop;
  bool handlerCalled = false;
  GuiPipe pipe(loop, sv[0], wp[1], [&](std::string_view) {
    handlerCalled = true;
  });

  writeAll(sv[1], "Exit\n");
  loop.run();

  CHECK(!handlerCalled);

  char buf[8] = {};
  const ssize_t n = ::read(wp[0], buf, sizeof(buf) - 1);
  CHECK_EQ(n, static_cast<ssize_t>(5));
  CHECK_EQ(std::string(buf), std::string("exit\n"));

  close(sv[0]);
  close(sv[1]);
  close(wp[0]);
  close(wp[1]);
}
