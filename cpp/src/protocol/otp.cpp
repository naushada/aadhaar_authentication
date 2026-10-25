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

void appendOtpAttrs(std::string& s, const OtpParams& p, std::string_view ts) {
  s += " ac=\"";
  s += p.ac;
  s += "\" lk=\"";
  s += p.lk;
  s += "\" sa=\"";
  s += p.sa;
  s += "\" tid=\"";
  s += p.tid;
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
  std::string s;
  s.reserve(1024);
  s += "<Otp";
  appendOtpAttrs(s, p, ts);
  s += "  <Opts ch=\"";
  s += formatCh(p.ch);
  s += "\"/>";
  return s;
}

std::string otpComposeC14nV16(const OtpParams& p, std::string_view ts) {
  std::string s;
  s.reserve(1024);
  s += "<Otp";
  appendOtpAttrs(s, p, ts);
  s += "  <Opts ch=\"";
  s += formatCh(p.ch);
  s += "\"></Opts>\n";
  s += "  \n";
  s += "</Otp>";
  return s;
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
  const std::string c14n = otpComposeC14nV16(p, ts);

  const auto digest = CryptoEngine::sha1(c14n);
  const std::string digestB64 =
      CryptoEngine::base64Encode(digest.data(), digest.size());

  const std::string signedInfo = uidai::xml::c14nSignedInfo(digestB64);
  const auto sig = CryptoEngine::rsaSha1Sign(ks.privateKey(), signedInfo);
  const std::string sigB64 =
      CryptoEngine::base64Encode(sig.data(), sig.size());

  std::string out = otpComposeXmlV16(p, ts);
  out += uidai::xml::composeSignatureBlock(digestB64, sigB64,
                                           ks.subjectName(),
                                           ks.certificateB64());
  out += "</Otp>";
  return out;
}

} // namespace uidai::protocol
