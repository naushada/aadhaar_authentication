#include "uidai/core/error.h"
#include "uidai/crypto/crypto_engine.h"

#include "test_util.h"

#include <cstdint>
#include <string>

using uidai::crypto::Bytes;
using uidai::crypto::CryptoEngine;

namespace {

std::string hex(const Bytes& b) {
  static const char* d = "0123456789abcdef";
  std::string s;
  s.reserve(b.size() * 2);
  for (uint8_t c : b) {
    s += d[c >> 4];
    s += d[c & 0xF];
  }
  return s;
}

std::string toStr(const Bytes& b) { return std::string(b.begin(), b.end()); }

} // namespace

TEST(sha1_known_vector) {
  CHECK_EQ(hex(CryptoEngine::sha1("abc")),
           "a9993e364706816aba3e25717850c26c9cd0d89d");
}

TEST(sha256_known_vector) {
  CHECK_EQ(hex(CryptoEngine::sha256("abc")),
           "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(base64_encode_known_vectors) {
  CHECK_EQ(CryptoEngine::base64Encode(""), "");
  CHECK_EQ(CryptoEngine::base64Encode("f"), "Zg==");
  CHECK_EQ(CryptoEngine::base64Encode("fo"), "Zm8=");
  CHECK_EQ(CryptoEngine::base64Encode("foo"), "Zm9v");
  CHECK_EQ(CryptoEngine::base64Encode("foob"), "Zm9vYg==");
}

TEST(base64_roundtrip) {
  std::string data = "UIDAI \x01\x02\x03 base64 round-trip \x7f";
  std::string b64 = CryptoEngine::base64Encode(data);
  CHECK_EQ(toStr(CryptoEngine::base64Decode(b64)), data);
}

TEST(aes256_gcm_roundtrip_and_determinism) {
  std::string key(32, 'k');
  std::string iv = "123456789012";
  std::string aad = "abcdefghijklmnop";
  std::string plain = "Hello, UIDAI AES-256-GCM round-trip!";

  auto ct = CryptoEngine::aes256GcmEncrypt(key, iv, aad, plain);
  CHECK_EQ(ct.size(), plain.size() + 16); // tag appended

  auto pt = CryptoEngine::aes256GcmDecrypt(
      key, iv, aad, std::string_view(reinterpret_cast<char*>(ct.data()), ct.size()));
  CHECK_EQ(toStr(pt), plain);

  auto ct2 = CryptoEngine::aes256GcmEncrypt(key, iv, aad, plain);
  CHECK_EQ(hex(ct), hex(ct2));
}

TEST(aes256_ecb_roundtrip) {
  std::string key(32, 'K');
  std::string plain = "ECB test payload (v1.6)";
  auto ct = CryptoEngine::aes256EcbEncrypt(key, plain);
  CHECK_EQ(ct.size() % 16, 0u); // PKCS#7 block multiple

  auto pt = CryptoEngine::aes256EcbDecrypt(
      key, std::string_view(reinterpret_cast<char*>(ct.data()), ct.size()));
  CHECK_EQ(toStr(pt), plain);
}

TEST(rsa_sign_verify_roundtrip) {
  // No keys available in a bare test run; validate the error path only when
  // keys are absent. Full RSA exercise lives in key_store_test via real keys.
  bool threw = false;
  try {
    CryptoEngine::rsaSha1Sign(nullptr, "x");
  } catch (const uidai::UidaiError&) {
    threw = true;
  }
  CHECK(threw);
}
