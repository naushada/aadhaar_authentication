#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// Forward-declare OpenSSL opaque types so this header stays free of OpenSSL
// includes (clients only need to know about EVP_PKEY* for the RSA entry points).
struct evp_pkey_st;
typedef struct evp_pkey_st EVP_PKEY;

namespace uidai::crypto {

using Bytes = std::vector<uint8_t>;

// Stateless crypto primitives. Every function throws uidai::UidaiError on
// failure. Key/iv/aad are passed as string_view over raw bytes.
//
// These reproduce the exact behavior of the C code:
//   * base64 has no line breaks (BIO_FLAGS_BASE64_NO_NL)
//   * AES-256-GCM uses a 12-byte IV and 16-byte AAD, tag appended (16 bytes)
//   * RSA uses PKCS#1 v1.5 padding
class CryptoEngine {
public:
  // ---- hashing ----
  static Bytes sha1(std::string_view data);
  static Bytes sha256(std::string_view data);

  // ---- base64 (RFC 4648, no line breaks) ----
  static std::string base64Encode(std::string_view data);
  static std::string base64Encode(const uint8_t* data, size_t len);
  static Bytes base64Decode(std::string_view data);

  // ---- random session key (32 bytes) ----
  static std::array<uint8_t, 32> randomSessionKey();

  // ---- AES-256-GCM (key = 32, iv = 12, aad = 16) ----
  // Encrypt returns ciphertext || 16-byte tag.
  static Bytes aes256GcmEncrypt(std::string_view key, std::string_view iv,
                                std::string_view aad, std::string_view plain);
  // Decrypt consumes ciphertext || 16-byte tag and returns the plaintext.
  static Bytes aes256GcmDecrypt(std::string_view key, std::string_view iv,
                                std::string_view aad, std::string_view cipherAndTag);

  // ---- AES-256-ECB with PKCS#7 (v1.6 Data/Hmac) ----
  static Bytes aes256EcbEncrypt(std::string_view key, std::string_view plain);
  static Bytes aes256EcbDecrypt(std::string_view key, std::string_view cipher);

  // ---- RSA (PKCS#1 v1.5), keys passed as borrowed EVP_PKEY* ----
  static Bytes rsaPublicEncrypt(EVP_PKEY* pub, std::string_view plain);
  static Bytes rsaPrivateDecrypt(EVP_PKEY* priv, std::string_view cipher);
  static Bytes rsaSha1Sign(EVP_PKEY* priv, std::string_view data);
  // Verifies a PKCS#1 v1.5 SHA-1 signature; returns true iff it validates.
  static bool rsaSha1Verify(EVP_PKEY* pub, std::string_view data,
                            std::string_view sig);
};

} // namespace uidai::crypto
