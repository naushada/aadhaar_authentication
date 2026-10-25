#include "uidai/protocol/ekyc.h"

#include "uidai/crypto/crypto_engine.h"

namespace uidai::protocol {

using uidai::crypto::CryptoEngine;

std::string ekycComposeXml(std::string_view authXml, const KycParams& p,
                           std::string_view ts) {
  // The inner signed Auth XML is carried as a single-line base64 string
  // (BIO_FLAGS_BASE64_NO_NL), exactly like the C's util_base64.
  const std::string b64 = CryptoEngine::base64Encode(authXml);

  // Attribute order differs per version (ekyc_compose_xml_v20/v21/v25):
  //   v2.0: ver ts ra rc mec lr de pfr
  //   v2.1: ver    ra rc mec lr de pfr
  //   v2.5: ver    ra rc     lr de pfr
  std::string out =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";
  out += "<Kyc ver=\"" + p.ver + "\"";
  if (p.ver == "2.0") {
    out += " ts=\"" + std::string(ts) + "\"";
  }
  out += " ra=\"" + p.ra + "\" rc=\"" + p.rc + "\"";
  if (p.ver == "2.0" || p.ver == "2.1") {
    out += " mec=\"" + p.mec + "\"";
  }
  out += " lr=\"" + p.lr + "\" de=\"" + p.de + "\" pfr=\"" + p.pfr + "\">\n";
  out += "  <Rad>" + b64 + "</Rad>\n</Kyc>";
  return out;
}

std::string ekycSignXmlV20(const AuthParams& auth, const KycParams& kyc,
                           std::string_view ts,
                           const std::array<uint8_t, 32>& sessionKey,
                           const crypto::KeyStore& ks) {
  const std::string authXml = authSignXmlV20(auth, ts, sessionKey, ks);
  return ekycComposeXml(authXml, kyc, ts);
}

} // namespace uidai::protocol
