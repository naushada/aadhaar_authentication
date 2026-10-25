#include "uidai/xml/xml_signature.h"

namespace uidai::xml {

std::string c14nSignedInfo(std::string_view digestB64) {
  std::string s;
  s.reserve(1024);
  s += "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n";
  s += "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>\n";
  s += "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>\n";
  s += "      <Reference URI=\"\">\n";
  s += "        <Transforms>\n";
  s += "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform>\n";
  s += "        </Transforms>\n";
  s += "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n";
  s += "        <DigestValue>";
  s += digestB64;
  s += "</DigestValue>\n";
  s += "      </Reference>\n";
  s += "    </SignedInfo>";
  return s;
}

std::string composeSignatureBlock(std::string_view digestB64,
                                  std::string_view signatureB64,
                                  std::string_view subject,
                                  std::string_view certificate) {
  std::string s;
  s.reserve(2048);
  s += "  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n";
  s += "    <SignedInfo>\n";
  s += "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n";
  s += "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n";
  s += "      <Reference URI=\"\">\n";
  s += "        <Transforms>\n";
  s += "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n";
  s += "        </Transforms>\n";
  s += "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n";
  s += "        <DigestValue>";
  s += digestB64;
  s += "</DigestValue>\n";
  s += "      </Reference>\n";
  s += "    </SignedInfo>\n";
  s += "    <SignatureValue>";
  s += signatureB64;
  s += "</SignatureValue>\n";
  s += "    <KeyInfo>\n";
  s += "      <X509Data>\n";
  s += "        <X509SubjectName>";
  s += subject;
  s += "</X509SubjectName>\n";
  s += "        <X509Certificate>";
  s += certificate;
  s += "</X509Certificate>\n";
  s += "      </X509Data>\n";
  s += "    </KeyInfo>\n";
  s += "  </Signature>\n";
  return s;
}

} // namespace uidai::xml
