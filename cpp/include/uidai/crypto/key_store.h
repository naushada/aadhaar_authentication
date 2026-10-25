#pragma once

#include <memory>
#include <string>

struct evp_pkey_st;
typedef struct evp_pkey_st EVP_PKEY;
struct x509_st;
typedef struct x509_st X509;

namespace uidai::crypto {

// Owns the AUA private key + certificate (from PKCS#12) and the UIDAI public
// certificate (.cer). Maps onto util_init + util_subject_certificate.
class KeyStore {
public:
  KeyStore(KeyStore&&) noexcept = default;
  KeyStore& operator=(KeyStore&&) noexcept = default;
  ~KeyStore();

  // Load the AUA signing key (PKCS#12) and the UIDAI public certificate.
  static KeyStore load(const std::string& p12Path,
                       const std::string& password,
                       const std::string& cerPath);

  EVP_PKEY* privateKey() const noexcept; // AUA signing key
  EVP_PKEY* publicKey() const noexcept;  // UIDAI public key (.cer)
  EVP_PKEY* signingPublicKey() const noexcept; // AUA cert's public key (verify)

  // Comma-separated subject, e.g. "C=IN,O=UIDAI,CN=Staging Signature".
  // Reproduces util_subject_certificate (X509_NAME_oneline -> strtok('/')).
  std::string subjectName() const;

  // base64(DER(cert)) — exactly the X509Certificate body embedded in the XML.
  std::string certificateB64() const;

  // notAfter of the UIDAI public certificate as "YYYYMMDD", reproduced from
  // auth_skey's ASN1_TIME_print + month-name index mapping. Feeds the <Skey
  // ci="…"> attribute.
  std::string publicCertExpiryYYYYMMDD() const;

private:
  KeyStore();
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace uidai::crypto
