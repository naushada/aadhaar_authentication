#pragma once

#include "uidai/crypto/key_store.h"
#include "uidai/protocol/auth.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace uidai::protocol {

// Attributes of the "kyc" request block (uidai_get_param "kyc").
struct KycParams {
  std::string ver; // "2.0" | "2.1" | "2.5"
  std::string ra;
  std::string rc;
  std::string mec; // v2.0 / v2.1 only
  std::string lr;
  std::string de;
  std::string pfr;
};

// base64(signed Auth XML) wrapped in <Kyc><Rad>…</Rad></Kyc>. The version
// selects the attribute set: v2.0 adds ts, v2.1 adds mec, v2.5 has neither.
// Ports ekyc_compose_xml_v20/v21/v25.
std::string ekycComposeXml(std::string_view authXml, const KycParams& p,
                           std::string_view ts);

// Full signed eKYC v2.0 request: signed Auth v2.0 → base64 → <Kyc> envelope.
// Ports ekyc_main_ex_v20.
std::string ekycSignXmlV20(const AuthParams& auth, const KycParams& kyc,
                           std::string_view ts,
                           const std::array<uint8_t, 32>& sessionKey,
                           const crypto::KeyStore& ks);

} // namespace uidai::protocol
