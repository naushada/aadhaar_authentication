#pragma once

#include <string>
#include <string_view>

namespace uidai::core {

// The UIDAI business outcome of a request, pulled out of the response XML.
struct Response {
  std::string ret;  // "y" (success) or "n" (failure)
  std::string err;
  std::string code;
  std::string actn;
  std::string info;

  bool ok() const { return ret == "y"; }
};

// Extract ret/err/code/actn/info attributes from the UIDAI response XML body
// (the first element — OtpRes/AuthRes/KycRes). Ports uidai_parse_rsp +
// uidai_get_rsp_param.
Response parseResponseXml(std::string_view body);

// The single-line Tcl command the GUI's response_display_response proc expects.
// Success: "response_display_response y \"\" <code> \"\" <info>\n".
// Failure: "response_display_response n <err> <code> <actn> <info>\n".
std::string formatDisplayResponse(const Response& r);

} // namespace uidai::core
