#pragma once

#include "uidai/crypto/key_store.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace uidai::protocol {

// Fields of the "auth"/"uses"/"meta"/"pi"/"demo" request blocks. Mirrors the
// attributes the C code pulls out of the Balaagh request via uidai_get_param /
// uidai_get_attr, exposed as plain strings for the port.
struct AuthParams {
  // <Auth …> attributes
  std::string ac;
  std::string lk;
  std::string rc;  // "Y" (resident) or "N"
  std::string sa;
  std::string tid; // empty for public devices
  std::string txn;
  std::string uid;
  std::string ver; // "2.0" | "2.5"

  // <Uses> flags — "1"/"0" as in the input request.
  std::string usesPi;
  std::string usesPa;
  std::string usesPfa;
  std::string usesBio;
  std::string usesPv;
  std::string usesDemo;
  std::string pvPin; // used only when usesPv == "1"
  std::string pvOtp;

  // <Meta> attributes (optional; empty = omitted).
  std::string metaDc;
  std::string metaDpId;
  std::string metaMc;
  std::string metaMi;
  std::string metaRdsId;
  std::string metaRdsVer;
  std::string metaUdc;

  // <Pi> attributes (optional; empty = omitted). piName may contain '+' which
  // auth_restore_str turns back into spaces.
  std::string piMs;
  std::string piMv;
  std::string piName;
  std::string piLname;
  std::string piLmv;
  std::string piGender;
  std::string piDob;
  std::string piDobt;
  std::string piAge;
  std::string piPhone;
  std::string piEmail;

  // <Demo lang="…"> (empty = no lang attribute).
  std::string demoLang;

  // <Bio> attributes (used only when usesBio == "1").
  std::string bioType;
  std::string bioPosh;
  std::string bioBs;
  std::string bioValue;
};

// iv = last 12 chars of ts, aad = last 16 chars of ts (auth_compute_ts).
struct AuthCryptoContext {
  std::string ts;  // "YYYY-MM-DDTHH:MM:SS"
  std::string iv;  // last 12 chars
  std::string aad; // last 16 chars
};

// Current UIDAI timestamp in local time (same format as otpTimestamp).
std::string authTimestamp();

// Derive iv/aad from a fixed/injected timestamp.
AuthCryptoContext authCryptoContext(std::string_view ts);

// "<Auth …>" opening tag (no trailing newline). auth_compose_auth_tag_v20.
std::string authComposeAuthTagV20(const AuthParams& p);

// "<Uses …/>" (self-closing, final form). auth_compose_uses_tag_v20.
std::string authComposeUsesTagV20(const AuthParams& p);
// "<Uses …></Uses>" (canonicalized form).
std::string authComposeUsesC14nV20(const AuthParams& p);

// "<Meta …/>" (self-closing). auth_compose_meta_tag_v20.
std::string authComposeMetaTagV20(const AuthParams& p);
// "<Meta …></Meta>" (canonicalized form).
std::string authComposeMetaC14nV20(const AuthParams& p);

// "<Pid …>…</Pid>" — the encrypted payload. auth_compose_pid_xml_v20.
std::string authComposePidXmlV20(const AuthParams& p, std::string_view ts);

// "<Skey ci=\"YYYYMMDD\">b64</Skey>". auth_skey: RSA(PKCS#1 v1.5) encrypt the
// session key with the UIDAI public key; ci is the public cert's notAfter.
std::string authComposeSkey(const std::array<uint8_t, 32>& sessionKey,
                            const crypto::KeyStore& ks);

// "<Data type=\"X\">b64</Data>". auth_data_v20: b64(ts || GCM(pidXml)).
std::string authComposeDataV20(std::string_view pidXml,
                               const AuthCryptoContext& ctx,
                               const std::array<uint8_t, 32>& sessionKey);

// "<Hmac>b64</Hmac>". auth_hmac_v20: b64(GCM(SHA256(pidXml))).
std::string authComposeHmacV20(std::string_view pidXml,
                               const AuthCryptoContext& ctx,
                               const std::array<uint8_t, 32>& sessionKey);

// Full signed Auth v2.0 request XML. auth_main_ex_v20: compose the canonical
// <Auth>, SHA-1 digest it, RSA-SHA1 sign the canonicalized <SignedInfo>, then
// embed the enveloped <Signature>. `sessionKey` is explicit so tests can inject
// a known key; pass CryptoEngine::randomSessionKey() for a fresh one.
std::string authSignXmlV20(const AuthParams& p, std::string_view ts,
                           const std::array<uint8_t, 32>& sessionKey,
                           const crypto::KeyStore& ks);

} // namespace uidai::protocol
