#include "uidai/protocol/otp.h"

#include "uidai/crypto/crypto_engine.h"
#include "uidai/xml/xml_signature.h"

#include <cstdio>
#include <cstdlib>
#include <ctime>

namespace uidai::protocol {

using uidai::crypto::CryptoEngine;

namespace {

// "%.2d" of atoi(ch), reproducing otp.c's <Opts ch="%02d"/> formatting.
std::string formatCh(const std::string& ch) {
  char buf[8];
  std::snprintf(buf, sizeof(buf), "%.2d", std::atoi(ch.c_str()));
  return buf;
}

// v1.6 carries a tid attribute; v2.5 drops it. Attribute order is otherwise
// identical: ac lk sa [tid] ts txn type uid ver.
void appendOtpAttrs(std::string& s, const OtpParams& p, std::string_view ts,
                    bool includeTid) {
  s += " ac=\"";
  s += p.ac;
  s += "\" lk=\"";
  s += p.lk;
  s += "\" sa=\"";
  s += p.sa;
  if (includeTid) {
    s += "\" tid=\"";
    s += p.tid;
  }
  s += "\" ts=\"";
  s += ts;
  s += "\" txn=\"";
  s += p.txn;
  s += "\" type=\"";
  s += p.type;
  s += "\" uid=\"";
  s += p.uid;
  s += "\" ver=\"";
  s += p.ver;
  s += "\">\n";
}

std::string composeOtp(const OtpParams& p, std::string_view ts,
                       bool includeTid) {
  std::string s;
  s.reserve(1024);
  s += "<Otp";
  appendOtpAttrs(s, p, ts, includeTid);
  s += "  <Opts ch=\"";
  s += formatCh(p.ch);
  s += "\"/>";
  return s;
}

std::string composeC14n(const OtpParams& p, std::string_view ts,
                        bool includeTid) {
  std::string s;
  s.reserve(1024);
  s += "<Otp";
  appendOtpAttrs(s, p, ts, includeTid);
  s += "  <Opts ch=\"";
  s += formatCh(p.ch);
  s += "\"></Opts>\n";
  s += "  \n";
  s += "</Otp>";
  return s;
}

std::string signXml(const OtpParams& p, std::string_view ts,
                    const crypto::KeyStore& ks, bool includeTid) {
  const std::string c14n = composeC14n(p, ts, includeTid);

  const auto digest = CryptoEngine::sha1(c14n);
  const std::string digestB64 =
      CryptoEngine::base64Encode(digest.data(), digest.size());

  const std::string signedInfo = uidai::xml::c14nSignedInfo(digestB64);
  const auto sig = CryptoEngine::rsaSha1Sign(ks.privateKey(), signedInfo);
  const std::string sigB64 =
      CryptoEngine::base64Encode(sig.data(), sig.size());

  std::string out = "<?xml version=\"1.0\" encoding=\"UTF-8\" "
                    "standalone=\"yes\"?>\n";
  out += composeOtp(p, ts, includeTid);
  out += "\n";
  out += uidai::xml::composeSignatureBlock(digestB64, sigB64,
                                           ks.subjectName(),
                                           ks.certificateB64());
  out += "</Otp>";
  return out;
}

} // namespace

std::string otpTimestamp() {
  std::time_t t = std::time(nullptr);
  std::tm ltm{};
  localtime_r(&t, &ltm);
  char buf[64];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d",
                ltm.tm_year + 1900, ltm.tm_mon + 1, ltm.tm_mday,
                ltm.tm_hour, ltm.tm_min, ltm.tm_sec);
  return buf;
}

std::string otpComposeOtpV16(const OtpParams& p, std::string_view ts) {
  return composeOtp(p, ts, true);
}

std::string otpComposeC14nV16(const OtpParams& p, std::string_view ts) {
  return composeC14n(p, ts, true);
}

std::string otpComposeXmlV16(const OtpParams& p, std::string_view ts) {
  std::string s;
  s.reserve(4096);
  s += "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";
  s += otpComposeOtpV16(p, ts);
  s += "\n";
  return s;
}

std::string otpSignXmlV16(const OtpParams& p, std::string_view ts,
                          const crypto::KeyStore& ks) {
  return signXml(p, ts, ks, true);
}

std::string otpComposeOtpV25(const OtpParams& p, std::string_view ts) {
  return composeOtp(p, ts, false);
}

std::string otpComposeC14nV25(const OtpParams& p, std::string_view ts) {
  return composeC14n(p, ts, false);
}

std::string otpComposeXmlV25(const OtpParams& p, std::string_view ts) {
  std::string s;
  s.reserve(4096);
  s += "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";
  s += otpComposeOtpV25(p, ts);
  s += "\n";
  return s;
}

std::string otpSignXmlV25(const OtpParams& p, std::string_view ts,
                          const crypto::KeyStore& ks) {
  return signXml(p, ts, ks, false);
}

} // namespace uidai::protocol
