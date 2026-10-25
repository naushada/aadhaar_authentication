#include "uidai/core/error.h"
#include "uidai/crypto/crypto_engine.h"
#include "uidai/crypto/key_store.h"
#include "uidai/protocol/auth.h"
#include "uidai/protocol/ekyc.h"
#include "uidai/xml/xml_signature.h"

#include "test_util.h"

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <string_view>

using uidai::crypto::CryptoEngine;
using uidai::crypto::KeyStore;
using namespace uidai::protocol;

namespace {

constexpr const char* kLk =
    "MBni88mRNM18dKdiVyDYCuddwXEQpl68dZAGBQ2nsOlGMzC9DkOVL5s";

KycParams goldenKyc() {
  KycParams p;
  p.ver = "2.0";
  p.ra = "Y";
  p.rc = "Y";
  p.mec = "1";
  p.lr = "Y";
  p.de = "Y";
  p.pfr = "Y";
  return p;
}

AuthParams goldenAuth() {
  AuthParams p;
  p.ac = "public";
  p.lk = kLk;
  p.rc = "Y";
  p.sa = "public";
  p.tid = "";
  p.txn = "TXN:BalaaghTesting";
  p.uid = "999938452218";
  p.ver = "2.0";
  p.usesPi = "1";
  p.usesPa = "0";
  p.usesPfa = "0";
  p.usesBio = "0";
  p.usesPv = "0";
  p.usesDemo = "1";
  p.metaUdc = "Balaagh";
  p.piMs = "E";
  p.piMv = "100";
  p.piName = "Naushad Ahmed";
  p.piGender = "M";
  p.piDobt = "V";
  return p;
}

std::array<uint8_t, 32> testKey() {
  std::array<uint8_t, 32> k{};
  for (int i = 0; i < 32; ++i) k[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
  return k;
}

std::string between(const std::string& s, const std::string& a,
                    const std::string& b) {
  const size_t i = s.find(a);
  if (i == std::string::npos) return {};
  const size_t j = s.find(b, i + a.size());
  if (j == std::string::npos) return {};
  return s.substr(i + a.size(), j - (i + a.size()));
}

} // namespace

TEST(ekyc_envelope_v20_matches_expected) {
  const KycParams p = goldenKyc();
  const std::string expected =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
      "<Kyc ver=\"2.0\" ts=\"2018-07-03T11:27:31\" ra=\"Y\" rc=\"Y\" mec=\"1\" "
      "lr=\"Y\" de=\"Y\" pfr=\"Y\">\n"
      "  <Rad>SEVMTE8=</Rad>\n"
      "</Kyc>";
  CHECK_EQ(ekycComposeXml("HELLO", p, "2018-07-03T11:27:31"), expected);
}

TEST(ekyc_envelope_v21_omits_ts) {
  KycParams p = goldenKyc();
  p.ver = "2.1";
  const std::string expected =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
      "<Kyc ver=\"2.1\" ra=\"Y\" rc=\"Y\" mec=\"1\" lr=\"Y\" de=\"Y\" pfr=\"Y\">\n"
      "  <Rad>SEVMTE8=</Rad>\n"
      "</Kyc>";
  CHECK_EQ(ekycComposeXml("HELLO", p, "2018-07-03T11:27:31"), expected);
}

TEST(ekyc_envelope_v25_omits_ts_and_mec) {
  KycParams p = goldenKyc();
  p.ver = "2.5";
  const std::string expected =
      "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
      "<Kyc ver=\"2.5\" ra=\"Y\" rc=\"Y\" lr=\"Y\" de=\"Y\" pfr=\"Y\">\n"
      "  <Rad>SEVMTE8=</Rad>\n"
      "</Kyc>";
  CHECK_EQ(ekycComposeXml("HELLO", p, "2018-07-03T11:27:31"), expected);
}

TEST(ekyc_sign_v20_wraps_valid_signed_auth) {
#ifdef UIDAI_REPO_ROOT
  const char* p12 = std::getenv("UIDAI_P12");
  const char* cer = std::getenv("UIDAI_CER");
  const char* pw = std::getenv("UIDAI_P12_PASSWORD");
  if (!p12) p12 = UIDAI_REPO_ROOT "/uidai/keys/Staging_Signature_PrivateKey.p12";
  if (!cer) cer = UIDAI_REPO_ROOT "/uidai/keys/uidai_auth_stage.cer";
  if (!pw) pw = "public";
#else
  const char* p12 = std::getenv("UIDAI_P12");
  const char* cer = std::getenv("UIDAI_CER");
  const char* pw = std::getenv("UIDAI_P12_PASSWORD");
#endif

  if (!p12 || !cer || !pw) {
    std::fprintf(stderr, "  SKIP (keys unavailable)\n");
    return;
  }

  try {
    KeyStore ks = KeyStore::load(p12, pw, cer);
    const std::string ts = "2018-07-03T11:27:31";
    const auto key = testKey();
    const AuthParams auth = goldenAuth();
    const KycParams kyc = goldenKyc();

    const std::string xml = ekycSignXmlV20(auth, kyc, ts, key, ks);

    // Envelope attributes, in the v2.0 order ver ts ra rc mec lr de pfr.
    CHECK(xml.find("<Kyc ver=\"2.0\" ts=\"2018-07-03T11:27:31\" ra=\"Y\" "
                   "rc=\"Y\" mec=\"1\" lr=\"Y\" de=\"Y\" pfr=\"Y\">") !=
          std::string::npos);

    // <Rad> carries a single-line base64 of the signed Auth XML.
    const std::string rad = between(xml, "<Rad>", "</Rad>");
    CHECK(!rad.empty());
    CHECK(rad.find('\n') == std::string::npos);
    const auto decoded = CryptoEngine::base64Decode(rad);
    const std::string authXml(decoded.begin(), decoded.end());

    CHECK(authXml.rfind("<?xml", 0) == 0);
    CHECK(authXml.find("<Auth ac=\"public\"") != std::string::npos);
    CHECK(authXml.find("</Auth>") != std::string::npos);
    // The <Pid> is GCM-encrypted, so it only surfaces as the opaque <Data>.
    CHECK(authXml.find("<Data type=\"X\">") != std::string::npos);

    // The carried Auth XML is itself a valid RSA-SHA1 signature. (The Skey
    // ciphertext is randomized PKCS#1 v1.5, so we can't byte-compare against a
    // separately-computed authSignXmlV20 — verify the signature instead.)
    const std::string digestB64 =
        between(authXml, "<DigestValue>", "</DigestValue>");
    const std::string sigB64 =
        between(authXml, "<SignatureValue>", "</SignatureValue>");
    CHECK(!digestB64.empty());
    CHECK(!sigB64.empty());
    const std::string signedInfo = uidai::xml::c14nSignedInfo(digestB64);
    const auto sig = CryptoEngine::base64Decode(sigB64);
    CHECK(CryptoEngine::rsaSha1Verify(
        ks.signingPublicKey(), signedInfo,
        std::string_view(reinterpret_cast<const char*>(sig.data()), sig.size())));
  } catch (const uidai::UidaiError& e) {
    std::fprintf(stderr, "  ekyc failed: %s\n", e.what());
    CHECK(false);
  }
}
