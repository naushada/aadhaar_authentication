#pragma once

#include <string>

namespace uidai {

// AUA/ASA credentials carried in every signed request. Fields map 1:1 onto the
// uidai_ctx_t members ac/sa/lk/private_fname/public_fname in uidai.h.
struct Credentials {
  std::string ac;         // AUA code, e.g. "public" / "registered"
  std::string sa;         // Sub-AUA code
  std::string lk;         // ASA license key
  std::string password;   // PKCS#12 passphrase for the private key
  std::string tid;        // "public" | "registered"
  std::string txnPrefix;  // transaction prefix, e.g. "SampleClient"
};

struct Config {
  Credentials creds;
  std::string host;           // UIDAI endpoint, e.g. developer.uidai.gov.in
  std::string uri;            // request path prefix
  std::string publicKeyFile;  // UIDAI public cert (.cer)
  std::string privateKeyFile; // AUA signing key (.p12)
};

} // namespace uidai
