#pragma once

#include "uidai/protocol/auth.h"
#include "uidai/protocol/ekyc.h"
#include "uidai/protocol/otp.h"

#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace uidai::transport {
class HttpTransport;
}

namespace uidai::protocol {

// A fully-parsed GUI request (the "/request?…&…" line). `host` and the target
// path/lk are resolved from the uidai/kyc blocks during parsing.
struct RequestSpec {
  std::string kind;  // "otp" | "auth" | "ekyc"

  std::string host;       // UIDAI endpoint host (uidai block)
  std::string targetUri;  // request path prefix (uidai.uri, or kyc.uri for eKYC)
  std::string targetLk;   // license key in the HTTP target (auth/otp lk, kyc lk for eKYC)

  std::string publicKeyFile;  // UIDAI .cer
  std::string privateKeyFile; // AUA .p12
  std::string password;       // PKCS#12 passphrase

  OtpParams otp;
  AuthParams auth;
  KycParams kyc;
};

// Parse a GUI request line into a RequestSpec. Throws uidai::UidaiError on an
// unsupported request kind. Ports uidai_parse_req.
RequestSpec parseRequest(std::string_view line);

// "http://<host><uri>/<ac>/<uid[0]>/<uid[1]>/<lk>" — the absolute request-target
// for a parsed request. Ports otp/auth/ekyc_compose_http_req.
std::string requestTarget(const RequestSpec& req);

// Client facade: compose a signed request, POST it, parse the response, and
// return the GUI display line. Ports uidai_parse_req + otp/auth/ekyc_main_ex* +
// uidai_parse_rsp. A KeyStore is loaded per request from the crypto block.
class UidaiClient {
public:
  using TransportFactory = std::function<std::unique_ptr<transport::HttpTransport>(
      const std::string& host, unsigned short port)>;

  // A null factory selects the default LibeventTransport(host, port).
  explicit UidaiClient(TransportFactory factory = nullptr);

  // Handle one parsed request end-to-end and return the display line
  // ("response_display_response …\n"). Throws uidai::UidaiError on local
  // failures (config/crypto/transport).
  std::string handle(const RequestSpec& req);

private:
  TransportFactory factory_;
};

} // namespace uidai::protocol
