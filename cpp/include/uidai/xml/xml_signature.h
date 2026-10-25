#pragma once

#include <string>
#include <string_view>

namespace uidai::xml {

// Canonicalized <SignedInfo> — the exact string that is RSA-SHA1 signed.
// Reproduces util_c14n_signedinfo byte-for-byte.
std::string c14nSignedInfo(std::string_view digestB64);

// The <Signature> block appended into the request XML (non-canonicalized).
// Reproduces util_compose_final_xml byte-for-byte.
std::string composeSignatureBlock(std::string_view digestB64,
                                  std::string_view signatureB64,
                                  std::string_view subject,
                                  std::string_view certificate);

} // namespace uidai::xml
