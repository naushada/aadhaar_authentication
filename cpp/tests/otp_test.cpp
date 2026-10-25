#include "uidai/core/error.h"
#include "uidai/crypto/crypto_engine.h"
#include "uidai/crypto/key_store.h"
#include "uidai/protocol/otp.h"

#include "test_util.h"

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

using uidai::crypto::CryptoEngine;
using uidai::crypto::KeyStore;
using namespace uidai::protocol;

namespace {

OtpParams goldenParams() {
  OtpParams p;
  p.ac = "public";
  p.lk = "MBni88mRNM18dKdiVyDYCuddwXEQpl68dZAGBQ2nsOlGMzC9DkOVL5s";
  p.sa = "public";
  p.tid = "public";
  p.txn = "TXN:BalaaghTesting";
  p.type = "M";
  p.uid = "9701361361";
  p.ver = "1.6";
  p.ch = "01";
  return p;
}

std::string readFile(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return {};
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// otp_success.xml embeds the request inside a captured HTTP exchange; pull out
// just the signed XML document body (from <?xml to </Otp>).
std::string extractXmlBody(const std::string& s) {
  const std::size_t a = s.find("<?xml");
  const std::size_t b = s.find("</Otp>");
  if (a == std::string::npos || b == std::string::npos) return {};
  return s.substr(a, b + 6 - a);
}

} // namespace

TEST(otp_c14n_v16_matches_golden) {
  const std::string ts = "2018-06-27T12:13:24";
  const OtpParams p = goldenParams();

  const std::string expected =
      "<Otp ac=\"public\" lk=\"MBni88mRNM18dKdiVyDYCuddwXEQpl68dZAGBQ2nsOlGMzC9DkOVL5s\" "
      "sa=\"public\" tid=\"public\" ts=\"2018-06-27T12:13:24\" txn=\"TXN:BalaaghTesting\" "
      "type=\"M\" uid=\"9701361361\" ver=\"1.6\">\n"
      "  <Opts ch=\"01\"></Opts>\n"
      "  \n"
      "</Otp>";

  CHECK_EQ(otpComposeC14nV16(p, ts), expected);

  // External oracle from otp_success.xml: SHA-1 of the canonical form, base64.
  const auto d = CryptoEngine::sha1(expected);
  CHECK_EQ(CryptoEngine::base64Encode(d.data(), d.size()),
           std::string("62LrwodDm1yFup4PCO0SOxMIfRU="));
}

TEST(otp_partial_tag_v16_matches_golden) {
  const std::string ts = "2018-06-27T12:13:24";
  const OtpParams p = goldenParams();

  const std::string expected =
      "<Otp ac=\"public\" lk=\"MBni88mRNM18dKdiVyDYCuddwXEQpl68dZAGBQ2nsOlGMzC9DkOVL5s\" "
      "sa=\"public\" tid=\"public\" ts=\"2018-06-27T12:13:24\" txn=\"TXN:BalaaghTesting\" "
      "type=\"M\" uid=\"9701361361\" ver=\"1.6\">\n"
      "  <Opts ch=\"01\"/>";

  CHECK_EQ(otpComposeOtpV16(p, ts), expected);
}

TEST(otp_sign_v16_matches_golden_file) {
#ifdef UIDAI_REPO_ROOT
  const char* p12 = std::getenv("UIDAI_P12");
  const char* cer = std::getenv("UIDAI_CER");
  const char* pw = std::getenv("UIDAI_P12_PASSWORD");
  if (!p12) p12 = UIDAI_REPO_ROOT "/uidai/keys/Staging_Signature_PrivateKey.p12";
  if (!cer) cer = UIDAI_REPO_ROOT "/uidai/keys/uidai_auth_stage.cer";
  if (!pw) pw = "public";
  const std::string golden = readFile(UIDAI_REPO_ROOT "/otp_success.xml");
#else
  const char* p12 = std::getenv("UIDAI_P12");
  const char* cer = std::getenv("UIDAI_CER");
  const char* pw = std::getenv("UIDAI_P12_PASSWORD");
  const std::string golden;
#endif

  if (!p12 || !cer || !pw) {
    std::fprintf(stderr, "  SKIP (keys unavailable)\n");
    return;
  }
  if (golden.empty()) {
    std::fprintf(stderr, "  SKIP (golden otp_success.xml not found)\n");
    return;
  }

  try {
    KeyStore ks = KeyStore::load(p12, pw, cer);
    const std::string ts = "2018-06-27T12:13:24";
    const std::string xml = otpSignXmlV16(goldenParams(), ts, ks);

    const std::string expected = extractXmlBody(golden);
    CHECK(!expected.empty());
    CHECK_EQ(xml, expected);
  } catch (const uidai::UidaiError& e) {
    std::fprintf(stderr, "  sign failed: %s\n", e.what());
    CHECK(false);
  }
}
