#include "uidai/xml/xml_signature.h"

#include "test_util.h"

using uidai::xml::c14nSignedInfo;
using uidai::xml::composeSignatureBlock;

TEST(c14n_signed_info_matches_c_template) {
  const char* expected =
      "<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"
      "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"></CanonicalizationMethod>\n"
      "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"></SignatureMethod>\n"
      "      <Reference URI=\"\">\n"
      "        <Transforms>\n"
      "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"></Transform>\n"
      "        </Transforms>\n"
      "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"></DigestMethod>\n"
      "        <DigestValue>QUJDRA==</DigestValue>\n"
      "      </Reference>\n"
      "    </SignedInfo>";
  CHECK_EQ(c14nSignedInfo("QUJDRA=="), std::string(expected));
}

TEST(compose_signature_block_matches_c_template) {
  const char* expected =
      "  <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n"
      "    <SignedInfo>\n"
      "      <CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\"/>\n"
      "      <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>\n"
      "      <Reference URI=\"\">\n"
      "        <Transforms>\n"
      "          <Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/>\n"
      "        </Transforms>\n"
      "        <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>\n"
      "        <DigestValue>QUJDRA==</DigestValue>\n"
      "      </Reference>\n"
      "    </SignedInfo>\n"
      "    <SignatureValue>U0lH</SignatureValue>\n"
      "    <KeyInfo>\n"
      "      <X509Data>\n"
      "        <X509SubjectName>C=IN,O=UIDAI</X509SubjectName>\n"
      "        <X509Certificate>Q0VSVA==</X509Certificate>\n"
      "      </X509Data>\n"
      "    </KeyInfo>\n"
      "  </Signature>\n";
  CHECK_EQ(composeSignatureBlock("QUJDRA==", "U0lH", "C=IN,O=UIDAI", "Q0VSVA=="),
           std::string(expected));
}
