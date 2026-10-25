#include "uidai/core/logger.h"
#include "uidai/protocol/protocol.h"
#include "uidai/transport/transport.h"

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include <cstdio>

int main() {
  uidai::Logger::info("uidai_cpp M0 scaffold");
  uidai::Logger::info(uidai::protocol::moduleName());

  std::fprintf(stderr, "libevent 0x%08x\n",
               uidai::transport::libeventVersionNumber());

  // Exercise a real libcrypto symbol so linking is proven, not just the header.
  uidai::Logger::info(OpenSSL_version(OPENSSL_VERSION));

  return 0;
}
