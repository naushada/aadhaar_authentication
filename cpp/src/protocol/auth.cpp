#include "uidai/protocol/auth.h"

#include "uidai/crypto/crypto_engine.h"
#include "uidai/xml/xml_signature.h"

#include <cstdio>
#include <ctime>
#include <string>

namespace uidai::protocol {

using uidai::crypto::CryptoEngine;

namespace {

// auth_restore_str: turn '+' back into spaces (URL-encoded name).
std::string restoreStr(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) out += (c == '+') ? ' ' : c;
  return out;
}

// auth_compose_uses_tag_v20 attribute list, up to the point where the final
// (/>) and canonicalized (></Uses>) forms diverge.
std::string usesAttrs(const AuthParams& p) {
  std::string s;

  // Bio (bt is emitted alongside bio="y").
  if (p.usesBio == "1") {
    s += " bio=\"y\" bt=\"y\"";
  } else {
    s += " bio=\"n\"";
  }

  // Otp / pin (pv block).
  if (p.usesPv == "1") {
    if (!p.pvPin.empty()) {
      s += " pin=\"y\"";
    } else if (!p.pvOtp.empty()) {
      s += " otp=\"y\"";
    } else {
      s += " otp=\"n\"";
    }
  } else {
    s += " otp=\"n\"";
  }

  // Pa.
  s += (p.usesPa == "1") ? " pa=\"y\"" : " pa=\"n\"";

  // Pfa.
  s += (p.usesPfa == "1") ? " pfa=\"y\"" : " pfa=\"n\"";

  // Pi.
  s += (p.usesPi == "1") ? " pi=\"y\"" : " pi=\"n\"";

  // pin — always emitted, always "n" (faithful to the C quirk).
  s += " pin=\"n\"";
  return s;
}

// auth_compose_meta_tag_v20 attribute list.
std::string metaAttrs(const AuthParams& p) {
  std::string s;
  if (!p.metaDc.empty()) s += " dc=\"" + p.metaDc + "\"";
  if (!p.metaDpId.empty()) s += " dpId=\"" + p.metaDpId + "\"";
  if (!p.metaMc.empty()) s += " mc=\"" + p.metaMc + "\"";
  if (!p.metaMi.empty()) s += " mi=\"" + p.metaMi + "\"";
  if (!p.metaRdsId.empty()) s += " rdsId=\"" + p.metaRdsId + "\"";
  if (!p.metaRdsVer.empty()) s += " rdsVer=\"" + p.metaRdsVer + "\"";
  if (!p.metaUdc.empty()) s += " udc=\"" + p.metaUdc + "\"";
  return s;
}

// auth_compose_pi_v16.
std::string composePi(const AuthParams& p) {
  std::string s = "\n    <Pi";
  if (!p.piMs.empty()) s += " ms=\"" + p.piMs + "\"";
  if (!p.piMv.empty()) s += " mv=\"" + p.piMv + "\"";
  if (!p.piName.empty()) s += " name=\"" + restoreStr(p.piName) + "\"";
  if (!p.piLname.empty()) s += " lname=\"" + p.piLname + "\"";
  if (!p.piLmv.empty()) s += " lmv=\"" + p.piLmv + "\"";
  if (!p.piGender.empty()) s += " gender=\"" + p.piGender + "\"";
  if (!p.piDob.empty()) s += " dob=\"" + p.piDob + "\"";
  if (!p.piDobt.empty()) s += " dobt=\"" + p.piDobt + "\"";
  if (!p.piAge.empty()) s += " age=\"" + p.piAge + "\"";
  if (!p.piPhone.empty()) s += " phone=\"" + p.piPhone + "\"";
  if (!p.piEmail.empty()) s += " email=\"" + p.piEmail + "\"";
  s += "/>\n";
  return s;
}

// auth_compose_demo_v16 (the "<Demo …>" opening tag only).
std::string composeDemo(const AuthParams& p) {
  std::string s = "  <Demo";
  if (!p.demoLang.empty() && p.demoLang.compare(0, 2, "NA") != 0) {
    s += " lang=\"" + p.demoLang + "\" ";
  }
  s += ">";
  return s;
}

// auth_compose_bio_v20.
std::string composeBio(const AuthParams& p) {
  std::string s = "  <Bios dih=\"\">\n    <Bio";
  if (!p.bioType.empty()) s += " type=\"" + p.bioType + "\"";
  if (!p.bioPosh.empty()) s += " posh=\"" + p.bioPosh + "\"";
  if (!p.bioBs.empty()) s += " bs=\"" + p.bioBs + "\"";
  if (!p.bioValue.empty()) s += ">" + p.bioValue + "</Bio>\n  </Bios>\n";
  return s;
}

// auth_compose_pv_v16.
std::string composePv(const AuthParams& p) {
  std::string s = "\n  <Pv";
  if (!p.pvOtp.empty()) s += " otp=\"" + p.pvOtp + "\"";
  if (!p.pvPin.empty()) s += " pin=\"" + p.pvPin + "\"";
  s += "/>\n";
  return s;
}

std::string_view sessionKeyView(const std::array<uint8_t, 32>& key) {
  return std::string_view(reinterpret_cast<const char*>(key.data()), key.size());
}

} // namespace

std::string authTimestamp() {
  std::time_t t = std::time(nullptr);
  std::tm ltm{};
  localtime_r(&t, &ltm);
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d",
                ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday,
                ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
  return buf;
}

AuthCryptoContext authCryptoContext(std::string_view ts) {
  AuthCryptoContext ctx;
  ctx.ts = std::string(ts);
  ctx.iv = ctx.ts.substr(ctx.ts.size() - 12);
  ctx.aad = ctx.ts.substr(ctx.ts.size() - 16);
  return ctx;
}

std::string authComposeAuthTagV20(const AuthParams& p) {
  std::string s = "<Auth ac=\"" + p.ac + "\" lk=\"" + p.lk + "\" rc=\"" + p.rc +
                  "\" sa=\"" + p.sa + "\" tid=\"" + p.tid +
                  "\" txn=\"" + p.txn + "\" uid=\"" + p.uid + "\" ver=\"" +
                  p.ver + "\">";
  return s;
}

std::string authComposeUsesTagV20(const AuthParams& p) {
  return "<Uses" + usesAttrs(p) + "/>";
}

std::string authComposeUsesC14nV20(const AuthParams& p) {
  return "<Uses" + usesAttrs(p) + "></Uses>";
}

std::string authComposeMetaTagV20(const AuthParams& p) {
  return "<Meta" + metaAttrs(p) + "/>";
}

std::string authComposeMetaC14nV20(const AuthParams& p) {
  return "<Meta" + metaAttrs(p) + "></Meta>";
}

std::string authComposePidXmlV20(const AuthParams& p, std::string_view ts) {
  std::string pid;
  pid.reserve(512);
  pid += "<Pid ts=\"" + std::string(ts) + "\" ver=\"2.0\" wadh=\"\">";

  const bool hasPi = p.usesPi == "1";
  const bool hasPa = p.usesPa == "1";
  const bool hasPfa = p.usesPfa == "1";

  if (hasPi || hasPa || hasPfa) {
    pid += "\n";
    pid += composeDemo(p);
    if (hasPi) pid += composePi(p);
    // pa / pfa composition lands with Auth v1.6 (M6).
    pid += "  </Demo>\n";
  }

  if (p.usesBio == "1") pid += composeBio(p);
  if (p.usesPv == "1") pid += composePv(p);

  pid += "</Pid>\n";
  return pid;
}

std::string authComposeSkey(const std::array<uint8_t, 32>& sessionKey,
                            const crypto::KeyStore& ks) {
  const std::string ci = ks.publicCertExpiryYYYYMMDD();
  const auto cipher = CryptoEngine::rsaPublicEncrypt(ks.publicKey(),
                                                     sessionKeyView(sessionKey));
  const std::string b64 = CryptoEngine::base64Encode(cipher.data(), cipher.size());
  return "<Skey ci=\"" + ci + "\">" + b64 + "</Skey>";
}

std::string authComposeDataV20(std::string_view pidXml,
                               const AuthCryptoContext& ctx,
                               const std::array<uint8_t, 32>& sessionKey) {
  const auto ct = CryptoEngine::aes256GcmEncrypt(sessionKeyView(sessionKey),
                                                 ctx.iv, ctx.aad, pidXml);
  std::string blob = ctx.ts;
  blob.append(reinterpret_cast<const char*>(ct.data()), ct.size());
  const std::string b64 = CryptoEngine::base64Encode(blob);
  return "<Data type=\"X\">" + b64 + "</Data>";
}

std::string authComposeHmacV20(std::string_view pidXml,
                               const AuthCryptoContext& ctx,
                               const std::array<uint8_t, 32>& sessionKey) {
  const auto digest = CryptoEngine::sha256(pidXml);
  const auto ct = CryptoEngine::aes256GcmEncrypt(
      sessionKeyView(sessionKey), ctx.iv, ctx.aad,
      std::string_view(reinterpret_cast<const char*>(digest.data()),
                       digest.size()));
  const std::string b64 = CryptoEngine::base64Encode(ct.data(), ct.size());
  return "<Hmac>" + b64 + "</Hmac>";
}

std::string authSignXmlV20(const AuthParams& p, std::string_view ts,
                           const std::array<uint8_t, 32>& sessionKey,
                           const crypto::KeyStore& ks) {
  const std::string authTag = authComposeAuthTagV20(p);
  const std::string usesTag = authComposeUsesTagV20(p);
  const std::string usesC14n = authComposeUsesC14nV20(p);
  const std::string metaTag = authComposeMetaTagV20(p);
  const std::string metaC14n = authComposeMetaC14nV20(p);

  const AuthCryptoContext ctx = authCryptoContext(ts);
  const std::string pidXml = authComposePidXmlV20(p, ts);
  const std::string skey = authComposeSkey(sessionKey, ks);
  const std::string data = authComposeDataV20(pidXml, ctx, sessionKey);
  const std::string hmac = authComposeHmacV20(pidXml, ctx, sessionKey);

  // Canonical <Auth> — the string that gets SHA-1 digested.
  const std::string c14n = authTag + "\n  " + usesC14n + "\n  " + metaC14n +
                           "\n  " + skey + "\n  " + hmac + "\n  " + data +
                           "\n  \n</Auth>";

  const auto digest = CryptoEngine::sha1(c14n);
  const std::string digestB64 =
      CryptoEngine::base64Encode(digest.data(), digest.size());
  const std::string signedInfo = uidai::xml::c14nSignedInfo(digestB64);
  const auto sig = CryptoEngine::rsaSha1Sign(ks.privateKey(), signedInfo);
  const std::string sigB64 =
      CryptoEngine::base64Encode(sig.data(), sig.size());

  std::string out =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";
  out += authTag + "\n  " + usesTag + "\n  " + metaTag + "\n  " + skey + "\n  " +
         hmac + "\n  " + data + "\n";
  out += uidai::xml::composeSignatureBlock(digestB64, sigB64, ks.subjectName(),
                                           ks.certificateB64());
  out += "</Auth>";
  return out;
}

} // namespace uidai::protocol
