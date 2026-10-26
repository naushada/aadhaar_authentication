#include "uidai/core/error.h"
#include "uidai/protocol/client.h"
#include "uidai/transport/http.h"
#include "uidai/transport/transport.h"

#include "test_util.h"

#include <cstdlib>
#include <cstdio>
#include <memory>
#include <string>

using namespace uidai::protocol;
using uidai::transport::HttpRequest;
using uidai::transport::HttpResponse;
using uidai::transport::HttpTransport;

namespace {

constexpr const char* kLk =
    "MBni88mRNM18dKdiVyDYCuddwXEQpl68dZAGBQ2nsOlGMzC9DkOVL5s";

const std::string kOtpReq =
    "/request?stage=staging&request=otp"
    "&otp={uid=999938452218,tid=public,txn=TXN:BalaaghTesting,ac=public,"
    "sa=public,ver=1.6,lk=" + std::string(kLk) + ",type=A}"
    "&opts={ch=01}"
    "&uidai={uri=/otp/1.6,host=developer.uidai.gov.in}"
    "&crypto={public=PUB.cer,private=PRIV.p12,password=public}";

const std::string kAuthReq =
    "/request?stage=staging&request=auth"
    "&auth={uid=999938452218,tid=public,txn=TXN:BalaaghTesting,ac=public,"
    "sa=public,ver=1.6,lk=" + std::string(kLk) + "}"
    "&uses={pi=1,pa=0,pfa=0,bio=0,pv=0,demo=1}"
    "&tkn={type=NA}"
    "&meta={udc=Balaagh,fdc=NA,idc=NA,pip=NA,lot=P,lov=500052}"
    "&pi={ms=E,mv=100,name=Naushad+Ahmed,gender=M,dobt=V}"
    "&demo={lang=NA}"
    "&uidai={uri=/uidauth,host=developer.uidai.gov.in}"
    "&crypto={public=PUB.cer,private=PRIV.p12,password=public}";

const std::string kEkycReq =
    "/request?stage=staging&request=ekyc"
    "&auth={uid=999938452218,tid=public,txn=TXN:BalaaghTesting,ac=public,"
    "sa=public,ver=2.0,lk=" + std::string(kLk) + "}"
    "&uses={pi=1,pa=0,pfa=0,bio=0,pv=0,demo=1}"
    "&meta={udc=Balaagh}"
    "&pi={ms=E,mv=100,name=Naushad+Ahmed,gender=M,dobt=V}"
    "&uidai={host=developer.uidai.gov.in}"
    "&kyc={lk=" + std::string(kLk) +
    ",uri=/kyc/2.0,ver=2.0,ra=NA,rc=Y,mec=NA,lr=NA,de=NA,pfr=NA}"
    "&crypto={public=PUB.cer,private=PRIV.p12,password=public}";

} // namespace

TEST(parse_request_otp) {
  RequestSpec r = parseRequest(kOtpReq);
  CHECK_EQ(r.kind, std::string("otp"));
  CHECK_EQ(r.host, std::string("developer.uidai.gov.in"));
  CHECK_EQ(r.targetUri, std::string("/otp/1.6"));
  CHECK_EQ(r.targetLk, std::string(kLk));
  CHECK_EQ(r.publicKeyFile, std::string("PUB.cer"));
  CHECK_EQ(r.privateKeyFile, std::string("PRIV.p12"));
  CHECK_EQ(r.password, std::string("public"));
  CHECK_EQ(r.otp.ac, std::string("public"));
  CHECK_EQ(r.otp.uid, std::string("999938452218"));
  CHECK_EQ(r.otp.ver, std::string("1.6"));
  CHECK_EQ(r.otp.type, std::string("A"));
  CHECK_EQ(r.otp.ch, std::string("01"));
}

TEST(parse_request_auth_v16) {
  RequestSpec r = parseRequest(kAuthReq);
  CHECK_EQ(r.kind, std::string("auth"));
  CHECK_EQ(r.targetUri, std::string("/uidauth"));
  CHECK_EQ(r.targetLk, std::string(kLk));
  CHECK_EQ(r.auth.ac, std::string("public"));
  CHECK_EQ(r.auth.uid, std::string("999938452218"));
  CHECK_EQ(r.auth.ver, std::string("1.6"));
  CHECK_EQ(r.auth.usesPi, std::string("1"));
  CHECK_EQ(r.auth.usesDemo, std::string("1"));
  CHECK_EQ(r.auth.metaUdc, std::string("Balaagh"));
  CHECK_EQ(r.auth.metaLot, std::string("P"));
  CHECK_EQ(r.auth.tknType, std::string("NA"));
  CHECK_EQ(r.auth.piName, std::string("Naushad+Ahmed"));
  CHECK_EQ(r.auth.piMv, std::string("100"));
  CHECK_EQ(r.auth.demoLang, std::string("NA"));
}

TEST(parse_request_ekyc) {
  RequestSpec r = parseRequest(kEkycReq);
  CHECK_EQ(r.kind, std::string("ekyc"));
  CHECK_EQ(r.host, std::string("developer.uidai.gov.in"));
  CHECK_EQ(r.targetUri, std::string("/kyc/2.0"));
  CHECK_EQ(r.targetLk, std::string(kLk));
  CHECK_EQ(r.auth.ac, std::string("public"));
  CHECK_EQ(r.auth.uid, std::string("999938452218"));
  CHECK_EQ(r.auth.ver, std::string("2.0"));
  CHECK_EQ(r.kyc.ver, std::string("2.0"));
  CHECK_EQ(r.kyc.rc, std::string("Y"));
  CHECK_EQ(r.kyc.mec, std::string("NA"));
}

TEST(parse_request_unsupported_throws) {
  bool threw = false;
  try {
    parseRequest("/request?request=bogus");
  } catch (const uidai::UidaiError&) {
    threw = true;
  }
  CHECK(threw);
}

TEST(request_target_otp) {
  RequestSpec r = parseRequest(kOtpReq);
  CHECK_EQ(requestTarget(r),
           std::string("http://developer.uidai.gov.in/otp/1.6/public/9/9/") +
               kLk);
}

TEST(request_target_auth) {
  RequestSpec r = parseRequest(kAuthReq);
  CHECK_EQ(requestTarget(r),
           std::string("http://developer.uidai.gov.in/uidauth/public/9/9/") +
               kLk);
}

TEST(request_target_ekyc) {
  RequestSpec r = parseRequest(kEkycReq);
  CHECK_EQ(requestTarget(r),
           std::string("http://developer.uidai.gov.in/kyc/2.0/public/9/9/") +
               kLk);
}

TEST(request_target_auth_https_with_asalk) {
  const std::string req =
      "/request?stage=staging&request=auth"
      "&auth={uid=999938452218,tid=public,txn=T,ac=public,sa=public,ver=2.5,"
      "lk=" + std::string(kLk) + ",asalk=ASA-KEY}"
      "&uidai={uri=/authserver/2.5,host=developer.uidai.gov.in,"
      "scheme=https,port=443}"
      "&crypto={public=PUB.cer,private=PRIV.p12,password=public}";
  RequestSpec r = parseRequest(req);
  CHECK_EQ(r.scheme, std::string("https"));
  CHECK(r.port == 443);
  CHECK_EQ(r.targetLk, std::string(kLk)); // lk stays the AUA key
  CHECK_EQ(r.asaLk, std::string("ASA-KEY"));
  CHECK_EQ(requestTarget(r),
           std::string(
               "https://developer.uidai.gov.in/authserver/2.5/public/9/9/ASA-KEY"));
}

TEST(parse_request_https_defaults_port_to_443) {
  const std::string req =
      "/request?request=auth"
      "&auth={uid=999938452218,ac=public,ver=2.5}"
      "&uidai={host=developer.uidai.gov.in,scheme=https}";
  RequestSpec r = parseRequest(req);
  CHECK_EQ(r.scheme, std::string("https"));
  CHECK(r.port == 443);
}

// A transport that records the outbound request and returns a canned response.
struct MockTransport : HttpTransport {
  HttpRequest* captured;
  HttpResponse response;
  HttpResponse perform(const HttpRequest& req, int) override {
    *captured = req;
    return response;
  }
};

TEST(client_handle_otp_end_to_end_with_mock) {
#ifdef UIDAI_REPO_ROOT
  const char* p12 = std::getenv("UIDAI_P12");
  const char* cer = std::getenv("UIDAI_CER");
  const char* pw = std::getenv("UIDAI_P12_PASSWORD");
  if (!p12) p12 = UIDAI_REPO_ROOT "/uidai/keys/Staging_Signature_PrivateKey.p12";
  if (!cer) cer = UIDAI_REPO_ROOT "/uidai/keys/uidai_auth_stage.cer";
  if (!pw) pw = "public";
#else
  const char* p12 = std::getenv("UIDAI_P12");
  const char* cer = std::getenv("UIDAI_CER");
  const char* pw = std::getenv("UIDAI_P12_PASSWORD");
#endif

  if (!p12 || !cer || !pw) {
    std::fprintf(stderr, "  SKIP (keys unavailable)\n");
    return;
  }

  RequestSpec req = parseRequest(kOtpReq);
  req.publicKeyFile = cer;
  req.privateKeyFile = p12;
  req.password = pw;

  HttpRequest captured;
  HttpResponse rsp;
  rsp.status = 200;
  rsp.reason = "OK";
  rsp.body =
      "<OtpRes txn=\"TXN:BalaaghTesting\" code=\"abc\" "
      "ts=\"2018-06-27T12:13:25+05:30\" ret=\"y\" info=\"01{x}\"/>";

  auto factory = [&](const std::string&, unsigned short, bool)
      -> std::unique_ptr<HttpTransport> {
    auto m = std::make_unique<MockTransport>();
    m->captured = &captured;
    m->response = rsp;
    return m;
  };

  UidaiClient client(factory);
  const std::string line = client.handle(req);

  CHECK_EQ(line, std::string("response_display_response y \"\" abc \"\" 01{x}\n"));
  CHECK_EQ(captured.method, std::string("POST"));
  CHECK_EQ(captured.target,
           std::string("http://developer.uidai.gov.in/otp/1.6/public/9/9/") +
               kLk);
  CHECK_EQ(captured.headers[1].first, std::string("Content-Type"));
  CHECK_EQ(captured.headers[1].second, std::string("text/xml"));
  CHECK(captured.body.rfind("<?xml", 0) == 0);
  CHECK(captured.body.find("<Otp ") != std::string::npos);
}
