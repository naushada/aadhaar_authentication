#include "uidai/core/response_parser.h"

#include "test_util.h"

#include <string>

using uidai::core::Response;
using uidai::core::formatDisplayResponse;
using uidai::core::parseResponseXml;

TEST(parse_otp_res_success) {
  const std::string body =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
      "<OtpRes txn=\"TXN:BalaaghTesting\" code=\"49fa6e95b1154dc3970f56dd5beb9f09\" "
      "ts=\"2018-06-27T12:13:25.428+05:30\" ret=\"y\" "
      "info=\"01{632b5bef}\"/>";

  Response r = parseResponseXml(body);
  CHECK(r.ok());
  CHECK_EQ(r.ret, std::string("y"));
  CHECK_EQ(r.code, std::string("49fa6e95b1154dc3970f56dd5beb9f09"));
  CHECK_EQ(r.info, std::string("01{632b5bef}"));
  CHECK_EQ(r.err, std::string(""));
}

TEST(parse_auth_res_failure) {
  const std::string body =
      "<AuthRes code=\"486503af\" err=\"511\" info=\"02{2ce68a02}\" ret=\"n\" "
      "ts=\"2018-06-25T08:54:31.463+05:30\" txn=\"TXN:BalaaghTesting\">"
      "<Signature/></AuthRes>";

  Response r = parseResponseXml(body);
  CHECK(!r.ok());
  CHECK_EQ(r.ret, std::string("n"));
  CHECK_EQ(r.err, std::string("511"));
  CHECK_EQ(r.code, std::string("486503af"));
  CHECK_EQ(r.info, std::string("02{2ce68a02}"));
}

TEST(parse_response_skips_xml_declaration) {
  const std::string body =
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<OtpRes ret=\"y\" "
      "code=\"c\" info=\"i\"/>";
  Response r = parseResponseXml(body);
  CHECK(r.ok());
  CHECK_EQ(r.code, std::string("c"));
}

TEST(format_display_response_success) {
  Response r;
  r.ret = "y";
  r.code = "c";
  r.info = "i";
  CHECK_EQ(formatDisplayResponse(r),
           std::string("response_display_response y \"\" c \"\" i\n"));
}

TEST(format_display_response_failure) {
  Response r;
  r.ret = "n";
  r.err = "511";
  r.code = "c";
  r.actn = "a";
  r.info = "i";
  CHECK_EQ(formatDisplayResponse(r),
           std::string("response_display_response n 511 c a i\n"));
}
