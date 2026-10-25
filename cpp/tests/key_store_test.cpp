#include "uidai/core/error.h"
#include "uidai/crypto/crypto_engine.h"
#include "uidai/crypto/key_store.h"

#include "test_util.h"

#include <cstdlib>
#include <cstdio>

using uidai::crypto::CryptoEngine;
using uidai::crypto::KeyStore;

TEST(key_store_load_bad_path) {
  bool threw = false;
  try {
    KeyStore::load("/nonexistent.p12", "x", "/nonexistent.cer");
  } catch (const uidai::UidaiError&) {
    threw = true;
  }
  CHECK(threw);
}

TEST(key_store_load_and_sign) {
  const char* p12 = std::getenv("UIDAI_P12");
  const char* cer = std::getenv("UIDAI_CER");
  const char* pw = std::getenv("UIDAI_P12_PASSWORD");
  if (!p12 || !cer || !pw) {
    std::fprintf(stderr,
                 "  SKIP (set UIDAI_P12/UIDAI_CER/UIDAI_P12_PASSWORD)\n");
    return;
  }

  try {
    KeyStore ks = KeyStore::load(p12, pw, cer);

    CHECK(ks.privateKey() != nullptr);
    CHECK(ks.publicKey() != nullptr);

    std::string subject = ks.subjectName();
    std::string certB64 = ks.certificateB64();
    CHECK(!subject.empty());
    CHECK(!certB64.empty());
    std::fprintf(stderr, "    subject = %s\n", subject.c_str());

    // RSA-SHA1 signature over a fixed string must be non-empty and
    // deterministic in structure (a fresh PKCS#1 v1.5 signature is
    // non-deterministic in bytes, but a 2048-bit key always yields 256 bytes).
    auto sig = CryptoEngine::rsaSha1Sign(ks.privateKey(), "signed-info");
    CHECK(!sig.empty());

    // Encrypt the session key with UIDAI's public key (the real request path
    // used by auth_skey). A 2048-bit RSA key yields a 256-byte ciphertext.
    std::string skey(32, 's');
    auto enc = CryptoEngine::rsaPublicEncrypt(ks.publicKey(), skey);
    CHECK(!enc.empty());

    // Self-consistency round-trip with the AUA private key: it carries its own
    // public components, so encrypt+decrypt round-trips. Validates
    // EVP_PKEY_encrypt/decrypt + PKCS#1 v1.5.
    auto selfEnc = CryptoEngine::rsaPublicEncrypt(ks.privateKey(), skey);
    auto dec = CryptoEngine::rsaPrivateDecrypt(ks.privateKey(),
        std::string_view(reinterpret_cast<char*>(selfEnc.data()), selfEnc.size()));
    CHECK_EQ(std::string(dec.begin(), dec.end()), skey);
  } catch (const uidai::UidaiError& e) {
    std::fprintf(stderr, "  load failed: %s\n", e.what());
    CHECK(false);
  }
}
