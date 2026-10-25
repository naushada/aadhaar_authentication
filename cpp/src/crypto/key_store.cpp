#include "uidai/crypto/key_store.h"

#include "uidai/core/error.h"
#include "uidai/crypto/crypto_engine.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#endif

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <vector>

namespace uidai::crypto {

namespace {

struct PkeyDel {
  void operator()(EVP_PKEY* p) const {
    if (p) EVP_PKEY_free(p);
  }
};
struct X509Del {
  void operator()(X509* p) const {
    if (p) X509_free(p);
  }
};
using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDel>;
using X509Ptr = std::unique_ptr<X509, X509Del>;

// OpenSSL 3.x moved RC2/3DES (used by UIDAI's 2017-era PKCS#12) into the
// "legacy" provider. Load it once so PKCS12_parse can read the demo keys.
void ensureLegacyProvider() {
  static std::once_flag flag;
  std::call_once(flag, [] {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    OSSL_PROVIDER_load(nullptr, "default");
    OSSL_PROVIDER_load(nullptr, "legacy");
#endif
  });
}

} // namespace

struct KeyStore::Impl {
  PkeyPtr priv;
  X509Ptr cert;
  PkeyPtr pub;
  X509Ptr pubCert; // UIDAI public certificate (.cer), kept for notAfter
};

KeyStore::KeyStore() : impl_(std::make_unique<Impl>()) {}
KeyStore::~KeyStore() = default;

KeyStore KeyStore::load(const std::string& p12Path, const std::string& password,
                        const std::string& cerPath) {
  ensureLegacyProvider();
  KeyStore ks;

  // --- private key + certificate from PKCS#12 ---
  FILE* fp = std::fopen(p12Path.c_str(), "rb");
  if (!fp) throw UidaiError("cannot open PKCS#12: " + p12Path);
  PKCS12* p12 = d2i_PKCS12_fp(fp, nullptr);
  std::fclose(fp);
  if (!p12) throw UidaiError("failed to parse PKCS#12: " + p12Path);

  EVP_PKEY* pkey = nullptr;
  X509* cert = nullptr;
  STACK_OF(X509)* ca = nullptr;
  if (PKCS12_parse(p12, password.c_str(), &pkey, &cert, &ca) != 1) {
    PKCS12_free(p12);
    throw UidaiError("PKCS12_parse failed (bad password?): " + p12Path);
  }
  PKCS12_free(p12);
  sk_X509_pop_free(ca, X509_free);

  ks.impl_->priv.reset(pkey);
  ks.impl_->cert.reset(cert);

  // --- UIDAI public key from .cer ---
  FILE* cfp = std::fopen(cerPath.c_str(), "rb");
  if (!cfp) throw UidaiError("cannot open certificate: " + cerPath);
  X509* ucert = PEM_read_X509(cfp, nullptr, nullptr, nullptr);
  std::fclose(cfp);
  if (!ucert) throw UidaiError("failed to read certificate: " + cerPath);

  EVP_PKEY* pub = X509_get0_pubkey(ucert);
  if (!pub) {
    X509_free(ucert);
    throw UidaiError("certificate has no public key: " + cerPath);
  }
  EVP_PKEY_up_ref(pub);
  ks.impl_->pub.reset(pub);
  ks.impl_->pubCert.reset(ucert); // keep the X509 for notAfter (auth_skey ci)

  return ks;
}

EVP_PKEY* KeyStore::privateKey() const noexcept { return impl_->priv.get(); }
EVP_PKEY* KeyStore::publicKey() const noexcept { return impl_->pub.get(); }
EVP_PKEY* KeyStore::signingPublicKey() const noexcept {
  return X509_get0_pubkey(impl_->cert.get());
}

std::string KeyStore::subjectName() const {
  char buf[512];
  X509_NAME_oneline(X509_get_subject_name(impl_->cert.get()), buf, sizeof(buf));
  std::string oneline(buf);

  // Reproduce util_subject_certificate: strtok_r on "/" (skips the leading
  // slash), append "token," for each, then the trailing comma is dropped by the
  // C's "rc = -1" accumulation. Net result: tokens joined by ",".
  std::string acc;
  size_t start = oneline.find_first_not_of('/');
  if (start != std::string::npos) {
    bool first = true;
    size_t pos = start;
    while (pos <= oneline.size()) {
      size_t slash = oneline.find('/', pos);
      std::string tok = oneline.substr(
          pos, slash == std::string::npos ? std::string::npos : slash - pos);
      if (!first) acc += ",";
      acc += tok;
      first = false;
      if (slash == std::string::npos) break;
      pos = slash + 1;
    }
  }
  return acc;
}

std::string KeyStore::certificateB64() const {
  unsigned char* der = nullptr;
  int len = i2d_X509(impl_->cert.get(), &der);
  if (len <= 0) throw UidaiError("i2d_X509 failed");
  std::string b64 = CryptoEngine::base64Encode(der, static_cast<size_t>(len));
  OPENSSL_free(der);

  // util_subject_certificate copies the PEM file text directly, so the
  // certificate keeps its 64-column line wrapping. Reproduce that: '\n' after
  // every 64 base64 chars, none after the final (possibly short) line.
  std::string wrapped;
  wrapped.reserve(b64.size() + b64.size() / 64 + 1);
  for (size_t i = 0; i < b64.size(); i += 64) {
    if (i) wrapped += '\n';
    wrapped.append(b64, i, std::min<size_t>(64, b64.size() - i));
  }
  return wrapped;
}

std::string KeyStore::publicCertExpiryYYYYMMDD() const {
  // Reproduce auth_skey: ASN1_TIME_print the notAfter, split on spaces, map the
  // month name through a 1-based table, then print "YYYY" "MM" "DD".
  const ASN1_TIME* expiry = X509_get0_notAfter(impl_->pubCert.get());
  if (!expiry) throw UidaiError("public certificate has no notAfter");

  BIO* bio = BIO_new(BIO_s_mem());
  if (!bio) throw UidaiError("BIO_new failed");
  if (!ASN1_TIME_print(bio, expiry)) {
    BIO_free(bio);
    throw UidaiError("ASN1_TIME_print failed");
  }

  char line[256] = {0};
  if (!BIO_gets(bio, line, static_cast<int>(sizeof(line)))) {
    BIO_free(bio);
    throw UidaiError("BIO_gets failed");
  }
  BIO_free(bio);

  // line looks like "Sep 16 00:00:00 2020 GMT" — tokens [month day time year …].
  std::vector<std::string> toks;
  char* save = nullptr;
  for (char* p = strtok_r(line, " ", &save); p; p = strtok_r(nullptr, " ", &save)) {
    toks.emplace_back(p);
  }
  if (toks.size() < 4) {
    throw UidaiError("unexpected notAfter format: " + std::string(line));
  }

  static const char* kMonths[] = {"Dummy", "Jan", "Feb", "Mar", "Apr", "May",
                                  "Jun",   "Jul", "Aug", "Sep", "Oct", "Nov",
                                  "Dec"};
  int idx = 0;
  for (int i = 0; i < 13; ++i) {
    if (std::strncmp(kMonths[i], toks[0].c_str(), toks[0].size()) == 0) {
      idx = i;
      break;
    }
  }

  char out[16];
  std::snprintf(out, sizeof(out), "%s%.2d%s", toks[3].c_str(), idx,
                toks[1].c_str());
  return out;
}

} // namespace uidai::crypto
