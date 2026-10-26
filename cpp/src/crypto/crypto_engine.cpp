#include "uidai/crypto/crypto_engine.h"

#include "uidai/core/error.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

namespace uidai::crypto {

namespace {

struct CipherCtx {
  EVP_CIPHER_CTX* p;
  CipherCtx() : p(EVP_CIPHER_CTX_new()) {      // allocate a cipher context
    if (!p) throw UidaiError("EVP_CIPHER_CTX_new failed");
  }
  ~CipherCtx() { EVP_CIPHER_CTX_free(p); }     // free the cipher context
  EVP_CIPHER_CTX* operator->() { return p; }
};

struct MdCtx {
  EVP_MD_CTX* p;
  MdCtx() : p(EVP_MD_CTX_new()) {              // allocate a digest context
    if (!p) throw UidaiError("EVP_MD_CTX_new failed");
  }
  ~MdCtx() { EVP_MD_CTX_free(p); }             // free the digest context
  EVP_MD_CTX* operator->() { return p; }
};

struct PkeyCtx {
  EVP_PKEY_CTX* p;
  explicit PkeyCtx(EVP_PKEY* key) : p(EVP_PKEY_CTX_new(key, nullptr)) {  // allocate a key-op context
    if (!p) throw UidaiError("EVP_PKEY_CTX_new failed");
  }
  ~PkeyCtx() { EVP_PKEY_CTX_free(p); }         // free the key-op context
  EVP_PKEY_CTX* operator->() { return p; }
};

Bytes digest(const EVP_MD* md, std::string_view data) {
  MdCtx ctx;
  Bytes out(EVP_MD_size(md));                  // digest length in bytes
  unsigned int outl = 0;
  if (EVP_DigestInit_ex(ctx.p, md, nullptr) != 1 ||   // start the digest
      EVP_DigestUpdate(ctx.p, data.data(), data.size()) != 1 ||  // feed data in
      EVP_DigestFinal_ex(ctx.p, out.data(), &outl) != 1) {       // finish and write digest
    throw UidaiError("message digest failed");
  }
  out.resize(outl);
  return out;
}

} // namespace

Bytes CryptoEngine::sha1(std::string_view data) { return digest(EVP_sha1(), data); }      // SHA-1 digest
Bytes CryptoEngine::sha256(std::string_view data) { return digest(EVP_sha256(), data); }  // SHA-256 digest

std::string CryptoEngine::base64Encode(const uint8_t* data, size_t len) {
  if (len == 0) return {};
  std::string out(((len + 2) / 3) * 4, '\0');
  int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data,
                          static_cast<int>(len));   // base64-encode (no line breaks)
  if (n < 0) throw UidaiError("base64 encode failed");
  out.resize(static_cast<size_t>(n));
  return out;
}

std::string CryptoEngine::base64Encode(std::string_view data) {
  return base64Encode(reinterpret_cast<const uint8_t*>(data.data()), data.size());  // delegate to buffer overload
}

Bytes CryptoEngine::base64Decode(std::string_view data) {
  std::string clean;
  clean.reserve(data.size());
  for (char c : data) {
    if (c != '\n' && c != '\r' && c != ' ' && c != '\t') clean.push_back(c);  // strip whitespace
  }
  if (clean.empty()) return {};

  // EVP_DecodeBlock returns n/4*3 bytes without subtracting '=' padding, so
  // account for it here (the C side used BIO with NO_NL, which strips padding).
  size_t pad = 0;
  while (pad < clean.size() && clean[clean.size() - 1 - pad] == '=') ++pad;  // count '=' padding

  Bytes out((clean.size() / 4) * 3);
  int n = EVP_DecodeBlock(out.data(),
                          reinterpret_cast<const unsigned char*>(clean.data()),
                          static_cast<int>(clean.size()));   // base64-decode into buffer
  if (n < 0) throw UidaiError("base64 decode failed");
  out.resize(static_cast<size_t>(n) - pad);
  return out;
}

std::array<uint8_t, 32> CryptoEngine::randomSessionKey() {
  std::array<uint8_t, 32> key{};
  if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {  // fill with CSPRNG bytes
    throw UidaiError("RAND_bytes failed");
  }
  return key;
}

Bytes CryptoEngine::aes256GcmEncrypt(std::string_view key, std::string_view iv,
                                     std::string_view aad, std::string_view plain) {
  if (key.size() != 32) throw UidaiError("AES-256-GCM key must be 32 bytes");
  if (iv.size() != 12) throw UidaiError("AES-256-GCM iv must be 12 bytes");
  if (aad.size() != 16) throw UidaiError("AES-256-GCM aad must be 16 bytes");

  CipherCtx ctx;
  Bytes out(plain.size() + 16);
  int len = 0, fin = 0;

  if (EVP_EncryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)  // init GCM, no key/iv yet
    throw UidaiError("GCM init failed");
  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1)  // set 12-byte IV length
    throw UidaiError("GCM set IV length failed");
  if (EVP_EncryptInit_ex(ctx.p, nullptr, nullptr,
                         reinterpret_cast<const unsigned char*>(key.data()),
                         reinterpret_cast<const unsigned char*>(iv.data())) != 1)  // supply key and IV
    throw UidaiError("GCM set key/iv failed");
  if (EVP_EncryptUpdate(ctx.p, nullptr, &len,
                        reinterpret_cast<const unsigned char*>(aad.data()),
                        static_cast<int>(aad.size())) != 1)  // authenticate AAD (no output)
    throw UidaiError("GCM set aad failed");
  if (EVP_EncryptUpdate(ctx.p, out.data(), &len,
                        reinterpret_cast<const unsigned char*>(plain.data()),
                        static_cast<int>(plain.size())) != 1)  // encrypt plaintext
    throw UidaiError("GCM encrypt failed");
  if (EVP_EncryptFinal_ex(ctx.p, out.data() + len, &fin) != 1)  // finish (flush final block)
    throw UidaiError("GCM finalize failed");

  int total = len + fin;
  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_GET_TAG, 16, out.data() + total) != 1)  // read 16-byte auth tag
    throw UidaiError("GCM get tag failed");

  out.resize(static_cast<size_t>(total) + 16);
  return out;
}

Bytes CryptoEngine::aes256GcmDecrypt(std::string_view key, std::string_view iv,
                                     std::string_view aad, std::string_view cipherAndTag) {
  if (key.size() != 32) throw UidaiError("AES-256-GCM key must be 32 bytes");
  if (iv.size() != 12) throw UidaiError("AES-256-GCM iv must be 12 bytes");
  if (aad.size() != 16) throw UidaiError("AES-256-GCM aad must be 16 bytes");
  if (cipherAndTag.size() < 16) throw UidaiError("GCM ciphertext+tag too short");

  const size_t cipherLen = cipherAndTag.size() - 16;  // tag is the last 16 bytes
  CipherCtx ctx;
  Bytes out(cipherLen);
  int len = 0, fin = 0;

  if (EVP_DecryptInit_ex(ctx.p, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)  // init GCM decrypt
    throw UidaiError("GCM decrypt init failed");
  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1)  // set 12-byte IV length
    throw UidaiError("GCM set IV length failed");
  if (EVP_DecryptInit_ex(ctx.p, nullptr, nullptr,
                         reinterpret_cast<const unsigned char*>(key.data()),
                         reinterpret_cast<const unsigned char*>(iv.data())) != 1)  // supply key and IV
    throw UidaiError("GCM set key/iv failed");
  if (EVP_DecryptUpdate(ctx.p, nullptr, &len,
                        reinterpret_cast<const unsigned char*>(aad.data()),
                        static_cast<int>(aad.size())) != 1)  // authenticate AAD (no output)
    throw UidaiError("GCM set aad failed");
  if (cipherLen > 0 &&
      EVP_DecryptUpdate(ctx.p, out.data(), &len,
                        reinterpret_cast<const unsigned char*>(cipherAndTag.data()),
                        static_cast<int>(cipherLen)) != 1)  // decrypt ciphertext
    throw UidaiError("GCM decrypt failed");
  if (EVP_CIPHER_CTX_ctrl(ctx.p, EVP_CTRL_GCM_SET_TAG, 16,
                          const_cast<unsigned char*>(
                              reinterpret_cast<const unsigned char*>(cipherAndTag.data()) + cipherLen)) != 1)  // set expected tag
    throw UidaiError("GCM set tag failed");
  if (EVP_DecryptFinal_ex(ctx.p, out.data() + len, &fin) != 1)  // verify tag and finish
    throw UidaiError("GCM authentication failed");

  out.resize(static_cast<size_t>(len) + fin);
  return out;
}

Bytes CryptoEngine::aes256EcbEncrypt(std::string_view key, std::string_view plain) {
  if (key.size() != 32) throw UidaiError("AES-256-ECB key must be 32 bytes");

  CipherCtx ctx;
  Bytes out(plain.size() + 16);
  int len = 0, fin = 0;

  if (EVP_EncryptInit_ex(ctx.p, EVP_aes_256_ecb(), nullptr,
                         reinterpret_cast<const unsigned char*>(key.data()), nullptr) != 1)  // init ECB with key
    throw UidaiError("ECB encrypt init failed");
  if (EVP_CIPHER_CTX_set_padding(ctx.p, 1) != 1)  // enable PKCS#7 padding
    throw UidaiError("ECB set PKCS#7 padding failed");
  if (EVP_EncryptUpdate(ctx.p, out.data(), &len,
                        reinterpret_cast<const unsigned char*>(plain.data()),
                        static_cast<int>(plain.size())) != 1)  // encrypt plaintext
    throw UidaiError("ECB encrypt failed");
  if (EVP_EncryptFinal_ex(ctx.p, out.data() + len, &fin) != 1)  // write the padding block
    throw UidaiError("ECB finalize failed");

  out.resize(static_cast<size_t>(len) + fin);
  return out;
}

Bytes CryptoEngine::aes256EcbDecrypt(std::string_view key, std::string_view cipher) {
  if (key.size() != 32) throw UidaiError("AES-256-ECB key must be 32 bytes");

  CipherCtx ctx;
  Bytes out(cipher.size());
  int len = 0, fin = 0;

  if (EVP_DecryptInit_ex(ctx.p, EVP_aes_256_ecb(), nullptr,
                         reinterpret_cast<const unsigned char*>(key.data()), nullptr) != 1)  // init ECB decrypt with key
    throw UidaiError("ECB decrypt init failed");
  if (EVP_CIPHER_CTX_set_padding(ctx.p, 1) != 1)  // enable PKCS#7 padding
    throw UidaiError("ECB set PKCS#7 padding failed");
  if (EVP_DecryptUpdate(ctx.p, out.data(), &len,
                        reinterpret_cast<const unsigned char*>(cipher.data()),
                        static_cast<int>(cipher.size())) != 1)  // decrypt ciphertext
    throw UidaiError("ECB decrypt failed");
  if (EVP_DecryptFinal_ex(ctx.p, out.data() + len, &fin) != 1)  // strip and verify padding
    throw UidaiError("ECB padding check failed");

  out.resize(static_cast<size_t>(len) + fin);
  return out;
}

Bytes CryptoEngine::rsaPublicEncrypt(EVP_PKEY* pub, std::string_view plain) {
  PkeyCtx ctx(pub);
  if (EVP_PKEY_encrypt_init(ctx.p) <= 0) throw UidaiError("rsa encrypt init failed");  // init public-key encrypt
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.p, RSA_PKCS1_PADDING) <= 0)  // use PKCS#1 v1.5 padding
    throw UidaiError("rsa set PKCS#1 padding failed");

  size_t outl = 0;
  if (EVP_PKEY_encrypt(ctx.p, nullptr, &outl,
                       reinterpret_cast<const unsigned char*>(plain.data()),
                       plain.size()) <= 0)  // query ciphertext size
    throw UidaiError("rsa encrypt size failed");

  Bytes out(outl);
  if (EVP_PKEY_encrypt(ctx.p, out.data(), &outl,
                       reinterpret_cast<const unsigned char*>(plain.data()),
                       plain.size()) <= 0)  // encrypt into buffer
    throw UidaiError("rsa encrypt failed");
  out.resize(outl);
  return out;
}

Bytes CryptoEngine::rsaPrivateDecrypt(EVP_PKEY* priv, std::string_view cipher) {
  PkeyCtx ctx(priv);
  if (EVP_PKEY_decrypt_init(ctx.p) <= 0) throw UidaiError("rsa decrypt init failed");  // init private-key decrypt
  if (EVP_PKEY_CTX_set_rsa_padding(ctx.p, RSA_PKCS1_PADDING) <= 0)  // use PKCS#1 v1.5 padding
    throw UidaiError("rsa set PKCS#1 padding failed");

  size_t outl = 0;
  if (EVP_PKEY_decrypt(ctx.p, nullptr, &outl,
                       reinterpret_cast<const unsigned char*>(cipher.data()),
                       cipher.size()) <= 0)  // query plaintext size
    throw UidaiError("rsa decrypt size failed");

  Bytes out(outl);
  if (EVP_PKEY_decrypt(ctx.p, out.data(), &outl,
                       reinterpret_cast<const unsigned char*>(cipher.data()),
                       cipher.size()) <= 0)  // decrypt into buffer
    throw UidaiError("rsa decrypt failed");
  out.resize(outl);
  return out;
}

Bytes CryptoEngine::rsaSha1Sign(EVP_PKEY* priv, std::string_view data) {
  MdCtx ctx;
  if (EVP_DigestSignInit(ctx.p, nullptr, EVP_sha1(), nullptr, priv) != 1)  // init SHA-1 signing
    throw UidaiError("rsa sign init failed");
  if (EVP_DigestSignUpdate(ctx.p, data.data(), data.size()) != 1)  // feed data to sign
    throw UidaiError("rsa sign update failed");

  size_t siglen = 0;
  if (EVP_DigestSignFinal(ctx.p, nullptr, &siglen) != 1)  // query signature size
    throw UidaiError("rsa sign size failed");

  Bytes sig(siglen);
  if (EVP_DigestSignFinal(ctx.p, sig.data(), &siglen) != 1)  // produce the signature
    throw UidaiError("rsa sign failed");
  sig.resize(siglen);
  return sig;
}

bool CryptoEngine::rsaSha1Verify(EVP_PKEY* pub, std::string_view data,
                                 std::string_view sig) {
  MdCtx ctx;
  if (EVP_DigestVerifyInit(ctx.p, nullptr, EVP_sha1(), nullptr, pub) != 1)  // init SHA-1 verification
    throw UidaiError("rsa verify init failed");
  if (EVP_DigestVerifyUpdate(ctx.p, data.data(), data.size()) != 1)  // feed data to verify
    throw UidaiError("rsa verify update failed");
  const int r = EVP_DigestVerifyFinal(
      ctx.p, reinterpret_cast<const unsigned char*>(sig.data()), sig.size());  // check the signature
  if (r < 0) throw UidaiError("rsa verify failed");
  return r == 1;
}

} // namespace uidai::crypto
