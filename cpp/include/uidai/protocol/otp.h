#pragma once

#include "uidai/crypto/key_store.h"

#include <string>
#include <string_view>

namespace uidai::protocol {

// Fields of the "otp" + "opts" request blocks (uidai_get_param "otp"/"opts").
struct OtpParams {
  std::string ac;
  std::string lk;
  std::string sa;
  std::string tid;
  std::string txn;
  std::string type; // "A" (Aadhaar) or "M" (mobile)
  std::string uid;
  std::string ver;  // "1.6" | "2.5"
  std::string ch;   // channel, e.g. "01"
};

// Current UIDAI timestamp: "%04d-%02d-%02dT%02d:%02d:%02d" in local time.
// Ports otp_get_ts.
std::string otpTimestamp();

// Canonicalized <Otp>…</Otp> — the string that gets SHA-1 digested (ports
// otp_compose_c14n_v16 byte-for-byte). `ts` is injected for determinism.
std::string otpComposeC14nV16(const OtpParams& p, std::string_view ts);

// The partial "<Otp …>\n  <Opts ch=\"01\"/>" (no closing tag). Ports
// otp_compose_otp_v16.
std::string otpComposeOtpV16(const OtpParams& p, std::string_view ts);

// "<?xml …?>\n" + partial Otp + "\n" — the request prefix before the
// <Signature> block. Ports otp_compose_xml_v16.
std::string otpComposeXmlV16(const OtpParams& p, std::string_view ts);

// Full signed OTP v1.6 request XML. Ports otp_sign_xml_v16: canonicalize the
// <Otp>, SHA-1 digest it, RSA-SHA1 sign the canonicalized <SignedInfo>, then
// embed the enveloped <Signature>.
std::string otpSignXmlV16(const OtpParams& p, std::string_view ts,
                          const crypto::KeyStore& ks);

} // namespace uidai::protocol
