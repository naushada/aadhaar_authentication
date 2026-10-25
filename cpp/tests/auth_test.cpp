#include "uidai/core/error.h"
#include "uidai/crypto/crypto_engine.h"
#include "uidai/crypto/key_store.h"
#include "uidai/protocol/auth.h"
#include "uidai/xml/xml_signature.h"

#include "test_util.h"

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

using uidai::crypto::CryptoEngine;
using uidai::crypto::KeyStore;
using namespace uidai::protocol;

namespace {

constexpr const char* kLk =
    "MBni88mRNM18dKdiVyDYCuddwXEQpl68dZAGBQ2nsOlGMzC9DkOVL5s";

AuthParams goldenParams() {
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

// The v1.6 golden (auth_success.xml) request block.
AuthParams auth16Params() {
  AuthParams p;
  p.ac = "public";
  p.lk = kLk;
  p.sa = "public";
  p.tid = "public";
  p.txn = "TXN:BalaaghTesting";
  p.uid = "999938452218";
  p.ver = "1.6";
  p.usesPi = "1";
  p.usesPa = "0";
  p.usesPfa = "0";
  p.usesBio = "0";
  p.usesPv = "0";
  p.usesDemo = "1";
  p.metaFdc = "NA";
  p.metaIdc = "NA";
  p.metaPip = "NA";
  p.metaLot = "P";
  p.metaLov = "500052";
  p.metaUdc = "Balaagh";
  p.tknType = "NA";
  p.piMs = "E";
  p.piMv = "100";
  p.piName = "Naushad+Ahmed";
  p.piGender = "M";
  p.piDobt = "V";
  p.demoLang = "NA";
  return p;
}

std::array<uint8_t, 32> testKey() {
  std::array<uint8_t, 32> k{};
  for (int i = 0; i < 32; ++i) k[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
  return k;
}

std::string_view keyView(const std::array<uint8_t, 32>& k) {
  return std::string_view(reinterpret_cast<const char*>(k.data()), k.size());
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

TEST(auth_tag_v20_matches_golden) {
  const AuthParams p = goldenParams();
  const std::string expected =
      std::string("<Auth ac=\"public\" lk=\"") + kLk +
      "\" rc=\"Y\" sa=\"public\" tid=\"\" txn=\"TXN:BalaaghTesting\" "
      "uid=\"999938452218\" ver=\"2.0\">";
  CHECK_EQ(authComposeAuthTagV20(p), expected);
}

TEST(uses_tag_v20_matches_golden) {
  const AuthParams p = goldenParams();
  CHECK_EQ(authComposeUsesTagV20(p),
           std::string("<Uses bio=\"n\" otp=\"n\" pa=\"n\" pfa=\"n\" pi=\"y\" "
                       "pin=\"n\"/>"));
  CHECK_EQ(authComposeUsesC14nV20(p),
           std::string("<Uses bio=\"n\" otp=\"n\" pa=\"n\" pfa=\"n\" pi=\"y\" "
                       "pin=\"n\"></Uses>"));
}

TEST(meta_tag_v20_matches_golden) {
  const AuthParams p = goldenParams();
  CHECK_EQ(authComposeMetaTagV20(p), std::string("<Meta udc=\"Balaagh\"/>"));
  CHECK_EQ(authComposeMetaC14nV20(p),
           std::string("<Meta udc=\"Balaagh\"></Meta>"));
}

TEST(pid_xml_v20_matches_golden) {
  const AuthParams p = goldenParams();
  const std::string expected =
      "<Pid ts=\"2018-07-03T11:27:31\" ver=\"2.0\" wadh=\"\">\n"
      "  <Demo>\n"
      "    <Pi ms=\"E\" mv=\"100\" name=\"Naushad Ahmed\" gender=\"M\" "
      "dobt=\"V\"/>\n"
      "  </Demo>\n"
      "</Pid>\n";
  CHECK_EQ(authComposePidXmlV20(p, "2018-07-03T11:27:31"), expected);
}

TEST(pi_name_restores_plus_to_space) {
  AuthParams p = goldenParams();
  p.piName = "Naushad+Ahmed";
  const std::string pid = authComposePidXmlV20(p, "2018-07-03T11:27:31");
  CHECK(pid.find("name=\"Naushad Ahmed\"") != std::string::npos);
}

TEST(auth_crypto_roundtrip_with_injected_key) {
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
    const AuthCryptoContext ctx = authCryptoContext(ts);
    const AuthParams p = goldenParams();
    const std::string pid = authComposePidXmlV20(p, ts);

    // Data = b64(ts || GCM(pid)); decrypt back to pid.
    const std::string data = authComposeDataV20(pid, ctx, key);
    const std::string dataB64 = between(data, "<Data type=\"X\">", "</Data>");
    CHECK(!dataB64.empty());
    const auto dataBlob = CryptoEngine::base64Decode(dataB64);
    CHECK_EQ(dataBlob.size(), ts.size() + pid.size() + 16);
    CHECK_EQ(std::string(dataBlob.begin(), dataBlob.begin() + ts.size()), ts);
    const auto dataCt =
        std::vector<uint8_t>(dataBlob.begin() + ts.size(), dataBlob.end());
    const auto dataPlain = CryptoEngine::aes256GcmDecrypt(
        keyView(key), ctx.iv, ctx.aad,
        std::string_view(reinterpret_cast<const char*>(dataCt.data()),
                         dataCt.size()));
    CHECK_EQ(std::string(dataPlain.begin(), dataPlain.end()), pid);

    // Hmac = b64(GCM(SHA256(pid))); decrypt back to SHA256(pid).
    const std::string hmac = authComposeHmacV20(pid, ctx, key);
    const std::string hmacB64 = between(hmac, "<Hmac>", "</Hmac>");
    CHECK(!hmacB64.empty());
    const auto hmacCt = CryptoEngine::base64Decode(hmacB64);
    const auto hmacPlain = CryptoEngine::aes256GcmDecrypt(
        keyView(key), ctx.iv, ctx.aad,
        std::string_view(reinterpret_cast<const char*>(hmacCt.data()),
                         hmacCt.size()));
    const auto sha = CryptoEngine::sha256(pid);
    CHECK_EQ(std::string(hmacPlain.begin(), hmacPlain.end()),
             std::string(sha.begin(), sha.end()));

    // Skey: ci value + a 2048-bit RSA ciphertext. PKCS#1 v1.5 *encryption* is
    // randomized, so we can't re-encrypt and compare (nor decrypt without the
    // UIDAI private key) — just check the shape.
    const std::string skey = authComposeSkey(key, ks);
    CHECK_EQ(between(skey, "ci=\"", "\">"), std::string("20200916"));
    const std::string skeyB64 = between(skey, "\">", "</Skey>");
    CHECK(!skeyB64.empty());
    CHECK(CryptoEngine::base64Decode(skeyB64).size() == 256);

    // Full signed XML: the embedded signature verifies, and the embedded
    // digest is SHA-1 of the canonical <Auth> rebuilt from the XML's own
    // Skey/Hmac/Data (Skey is randomized, so rebuild from the output).
    const std::string xml = authSignXmlV20(p, ts, key, ks);
    const std::string digestB64 = between(xml, "<DigestValue>", "</DigestValue>");
    const std::string sigB64 = between(xml, "<SignatureValue>", "</SignatureValue>");
    CHECK(!digestB64.empty());
    CHECK(!sigB64.empty());
    const std::string signedInfo = uidai::xml::c14nSignedInfo(digestB64);
    const auto sig = CryptoEngine::base64Decode(sigB64);
    CHECK(CryptoEngine::rsaSha1Verify(
        ks.signingPublicKey(), signedInfo,
        std::string_view(reinterpret_cast<const char*>(sig.data()), sig.size())));

    const std::string skeyXml = "<Skey" + between(xml, "<Skey", "</Skey>") + "</Skey>";
    const std::string hmacXml =
        "<Hmac>" + between(xml, "<Hmac>", "</Hmac>") + "</Hmac>";
    const std::string dataXml =
        "<Data type=\"X\">" + between(xml, "<Data type=\"X\">", "</Data>") + "</Data>";
    const std::string c14n = authComposeAuthTagV20(p) + "\n  " +
                             authComposeUsesC14nV20(p) + "\n  " +
                             authComposeMetaC14nV20(p) + "\n  " + skeyXml + "\n  " +
                             hmacXml + "\n  " + dataXml + "\n  \n</Auth>";
    const auto digest = CryptoEngine::sha1(c14n);
    CHECK_EQ(CryptoEngine::base64Encode(digest.data(), digest.size()), digestB64);
  } catch (const uidai::UidaiError& e) {
    std::fprintf(stderr, "  auth failed: %s\n", e.what());
    CHECK(false);
  }
}

TEST(meta_tag_v25_matches_expected) {
  const AuthParams p = goldenParams();
  // Only udc is set in the golden; v2.5 drops udc and emits the rest empty.
  CHECK_EQ(authComposeMetaTagV25(p),
           std::string("<Meta dc=\"\" dpId=\"\" mc=\"\" mi=\"\" rdsId=\"\" "
                       "rdsVer=\"\"/>"));
  CHECK_EQ(authComposeMetaC14nV25(p),
           std::string("<Meta dc=\"\" dpId=\"\" mc=\"\" mi=\"\" rdsId=\"\" "
                       "rdsVer=\"\"></Meta>"));

  // Full attribute order dc dpId mc mi rdsId rdsVer.
  AuthParams q = p;
  q.metaDc = "dc";
  q.metaDpId = "dp";
  q.metaMc = "mc";
  q.metaMi = "mi";
  q.metaRdsId = "ri";
  q.metaRdsVer = "rv";
  CHECK_EQ(authComposeMetaTagV25(q),
           std::string("<Meta dc=\"dc\" dpId=\"dp\" mc=\"mc\" mi=\"mi\" "
                       "rdsId=\"ri\" rdsVer=\"rv\"/>"));
}

TEST(auth_sign_v25_verifies) {
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
    const AuthParams p = goldenParams();

    const std::string xml = authSignXmlV25(p, ts, key, ks);

    const std::string digestB64 = between(xml, "<DigestValue>", "</DigestValue>");
    const std::string sigB64 = between(xml, "<SignatureValue>", "</SignatureValue>");
    CHECK(!digestB64.empty());
    CHECK(!sigB64.empty());
    const std::string signedInfo = uidai::xml::c14nSignedInfo(digestB64);
    const auto sig = CryptoEngine::base64Decode(sigB64);
    CHECK(CryptoEngine::rsaSha1Verify(
        ks.signingPublicKey(), signedInfo,
        std::string_view(reinterpret_cast<const char*>(sig.data()), sig.size())));

    // Digest matches the v2.5 canonical form (meta v2.5) rebuilt from the XML's
    // own randomized Skey/Hmac/Data.
    const std::string skeyXml = "<Skey" + between(xml, "<Skey", "</Skey>") + "</Skey>";
    const std::string hmacXml =
        "<Hmac>" + between(xml, "<Hmac>", "</Hmac>") + "</Hmac>";
    const std::string dataXml =
        "<Data type=\"X\">" + between(xml, "<Data type=\"X\">", "</Data>") + "</Data>";
    const std::string c14n = authComposeAuthTagV20(p) + "\n  " +
                             authComposeUsesC14nV20(p) + "\n  " +
                             authComposeMetaC14nV25(p) + "\n  " + skeyXml + "\n  " +
                             hmacXml + "\n  " + dataXml + "\n  \n</Auth>";
    const auto digest = CryptoEngine::sha1(c14n);
    CHECK_EQ(CryptoEngine::base64Encode(digest.data(), digest.size()), digestB64);
  } catch (const uidai::UidaiError& e) {
    std::fprintf(stderr, "  auth failed: %s\n", e.what());
    CHECK(false);
  }
}

TEST(auth_tag_v16_matches_golden) {
  const AuthParams p = auth16Params();
  const std::string expected =
      std::string("<Auth ac=\"public\" lk=\"") + kLk +
      "\" sa=\"public\" tid=\"public\" txn=\"TXN:BalaaghTesting\" "
      "uid=\"999938452218\" ver=\"1.6\">";
  CHECK_EQ(authComposeAuthTagV16(p), expected);
}

TEST(meta_tag_v16_matches_golden) {
  const AuthParams p = auth16Params();
  const std::string expected =
      "<Meta fdc=\"NA\" idc=\"NA\" lot=\"P\" lov=\"500052\" pip=\"NA\" "
      "udc=\"Balaagh\"/>";
  CHECK_EQ(authComposeMetaTagV16(p), expected);
  const std::string c14n =
      "<Meta fdc=\"NA\" idc=\"NA\" lot=\"P\" lov=\"500052\" pip=\"NA\" "
      "udc=\"Balaagh\"></Meta>";
  CHECK_EQ(authComposeMetaC14nV16(p), c14n);
}

TEST(pid_xml_v16_matches_golden) {
  const AuthParams p = auth16Params();
  const std::string expected =
      "<Pid ts=\"2018-06-25T10:22:24\" ver=\"1.0\">\n"
      "  <Demo>\n"
      "    <Pi ms=\"E\" mv=\"100\" name=\"Naushad Ahmed\" gender=\"M\" "
      "dobt=\"V\"/>\n"
      "  </Demo>\n"
      "</Pid>\n";
  CHECK_EQ(authComposePidXmlV16(p, "2018-06-25T10:22:24"), expected);
}

TEST(auth_crypto_roundtrip_v16_with_injected_key) {
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
    const std::string ts = "2018-06-25T10:22:24";
    const auto key = testKey();
    const AuthParams p = auth16Params();
    const std::string pid = authComposePidXmlV16(p, ts);

    // Data = b64(ECB(pid)); decrypt back to pid.
    const std::string data = authComposeDataV16(pid, key);
    const std::string dataB64 = between(data, "<Data type=\"X\">", "</Data>");
    CHECK(!dataB64.empty());
    const auto dataCt = CryptoEngine::base64Decode(dataB64);
    const auto dataPlain = CryptoEngine::aes256EcbDecrypt(
        keyView(key),
        std::string_view(reinterpret_cast<const char*>(dataCt.data()),
                         dataCt.size()));
    CHECK_EQ(std::string(dataPlain.begin(), dataPlain.end()), pid);

    // Hmac = b64(ECB(SHA256(pid))); decrypt back to SHA256(pid).
    const std::string hmac = authComposeHmacV16(pid, key);
    const std::string hmacB64 = between(hmac, "<Hmac>", "</Hmac>");
    CHECK(!hmacB64.empty());
    const auto hmacCt = CryptoEngine::base64Decode(hmacB64);
    const auto hmacPlain = CryptoEngine::aes256EcbDecrypt(
        keyView(key),
        std::string_view(reinterpret_cast<const char*>(hmacCt.data()),
                         hmacCt.size()));
    const auto sha = CryptoEngine::sha256(pid);
    CHECK_EQ(std::string(hmacPlain.begin(), hmacPlain.end()),
             std::string(sha.begin(), sha.end()));

    // Skey shape (randomized PKCS#1 v1.5 encryption, so no re-encrypt compare).
    const std::string skey = authComposeSkey(key, ks);
    CHECK_EQ(between(skey, "ci=\"", "\">"), std::string("20200916"));

    // Full signed XML: signature verifies; digest matches the c14n rebuilt from
    // the XML's own randomized Skey/Hmac/Data.
    const std::string xml = authSignXmlV16(p, ts, key, ks);
    const std::string digestB64 = between(xml, "<DigestValue>", "</DigestValue>");
    const std::string sigB64 = between(xml, "<SignatureValue>", "</SignatureValue>");
    CHECK(!digestB64.empty());
    CHECK(!sigB64.empty());
    const std::string signedInfo = uidai::xml::c14nSignedInfo(digestB64);
    const auto sig = CryptoEngine::base64Decode(sigB64);
    CHECK(CryptoEngine::rsaSha1Verify(
        ks.signingPublicKey(), signedInfo,
        std::string_view(reinterpret_cast<const char*>(sig.data()), sig.size())));

    const std::string skeyXml = "<Skey" + between(xml, "<Skey", "</Skey>") + "</Skey>";
    const std::string hmacXml =
        "<Hmac>" + between(xml, "<Hmac>", "</Hmac>") + "</Hmac>";
    const std::string dataXml =
        "<Data type=\"X\">" + between(xml, "<Data type=\"X\">", "</Data>") + "</Data>";
    const std::string c14n = authComposeAuthTagV16(p) + "\n  " +
                             authComposeUsesC14nV20(p) + "\n  " +
                             authComposeMetaC14nV16(p) + "\n  " + skeyXml + "\n  " +
                             hmacXml + "\n  " + dataXml + "\n  \n</Auth>";
    const auto digest = CryptoEngine::sha1(c14n);
    CHECK_EQ(CryptoEngine::base64Encode(digest.data(), digest.size()), digestB64);
  } catch (const uidai::UidaiError& e) {
    std::fprintf(stderr, "  auth failed: %s\n", e.what());
    CHECK(false);
  }
}
