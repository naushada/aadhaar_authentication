#include "uidai/protocol/client.h"
#include "uidai/transport/event_loop.h"
#include "uidai/transport/gui_pipe.h"

#include <unistd.h>

#include <cstdio>
#include <exception>
#include <string>

#ifndef UIDAI_GUI_DIR
#define UIDAI_GUI_DIR "../uidai/gui"
#endif

namespace {

// fork()+execlp("wish") with the child's stdin/stdout mapped to the two pipes.
// childIn[1] (parent -> child stdin) and childOut[0] (child stdout -> parent)
// are the parent's ends. Ports uidai_spawn_gui.
int spawnGui(const int childIn[2], const int childOut[2]) {
  const pid_t pid = fork();
  if (pid < 0) {
    std::perror("fork");
    return -1;
  }
  if (pid == 0) {
    close(childIn[1]);
    close(childOut[0]);
    if (dup2(childIn[0], 0) < 0) std::perror("dup2 stdin");
    if (dup2(childOut[1], 1) < 0) std::perror("dup2 stdout");
    close(childIn[0]);
    close(childOut[1]);
    execlp("wish", "wish", nullptr);
    std::perror("execlp wish");
    _exit(1);
  }
  return static_cast<int>(pid);
}

} // namespace

int main(int argc, char* argv[]) {
  const char* guiDir = (argc > 1) ? argv[1] : UIDAI_GUI_DIR;

  // Interactive wish evals this from stdin to load the GUI into the Tk loop.
  const std::string bootCmd = std::string("set argv {") + guiDir +
                              "}; source " + guiDir + "/main.tk\n";

  int childIn[2];
  int childOut[2];
  if (pipe(childIn) < 0) {
    std::perror("pipe childIn");
    return 1;
  }
  if (pipe(childOut) < 0) {
    std::perror("pipe childOut");
    close(childIn[0]);
    close(childIn[1]);
    return 1;
  }

  const int guiPid = spawnGui(childIn, childOut);
  if (guiPid < 0) {
    close(childIn[0]);
    close(childIn[1]);
    close(childOut[0]);
    close(childOut[1]);
    return 1;
  }

  // Parent keeps the write end to the child's stdin and the read end of the
  // child's stdout.
  close(childIn[0]);
  close(childOut[1]);

  uidai::protocol::UidaiClient client;

  uidai::transport::EventLoop loop;
  uidai::transport::GuiPipe gui(
      loop, childOut[0], childIn[1],
      [&](std::string_view line) {
        try {
          const uidai::protocol::RequestSpec req =
              uidai::protocol::parseRequest(line);
          gui.send(client.handle(req));
        } catch (const std::exception& e) {
          std::fprintf(stderr, "uidai_cli: request error: %s\n", e.what());
          // Best-effort failure line so the GUI shows the local error.
          std::string err = "response_display_response n \"";
          err += e.what();
          err += "\" \"\" \"\" \"\"\n";
          gui.send(err);
        }
      });

  gui.send(bootCmd);
  loop.run();

  close(childIn[1]);
  close(childOut[0]);
  return 0;
}
