#include "uidai/protocol/client.h"

#include "uidai/core/error.h"
#include "uidai/core/parser.h"
#include "uidai/core/response_parser.h"
#include "uidai/crypto/crypto_engine.h"
#include "uidai/crypto/key_store.h"
#include "uidai/transport/http.h"
#include "uidai/transport/transport.h"

#include <string_view>

namespace uidai::protocol {

namespace {

using uidai::core::AttrParser;
using uidai::core::QueryParser;

// uidai_get_attr with a default: absent -> "" (mirrors the C code, where a
// missing attribute yields NULL and the compose functions skip empty strings).
std::string attr(const AttrParser& p, std::string_view name) {
  auto v = p.attr(name);
  return v ? std::move(*v) : std::string{};
}

bool startsWith(std::string_view s, std::string_view prefix) {
  return s.size() >= prefix.size() && s.substr(0, prefix.size()) == prefix;
}

void parseAuth(QueryParser& qp, RequestSpec& out) {
  out.auth.ac = attr(AttrParser(*qp.param("auth")), "ac");
  out.auth.lk = attr(AttrParser(*qp.param("auth")), "lk");
  out.auth.rc = attr(AttrParser(*qp.param("auth")), "rc");
  out.auth.sa = attr(AttrParser(*qp.param("auth")), "sa");
  out.auth.tid = attr(AttrParser(*qp.param("auth")), "tid");
  out.auth.txn = attr(AttrParser(*qp.param("auth")), "txn");
  out.auth.uid = attr(AttrParser(*qp.param("auth")), "uid");
  out.auth.ver = attr(AttrParser(*qp.param("auth")), "ver");

  if (auto uses = qp.param("uses")) {
    AttrParser u(*uses);
    out.auth.usesPi = attr(u, "pi");
    out.auth.usesPa = attr(u, "pa");
    out.auth.usesPfa = attr(u, "pfa");
    out.auth.usesBio = attr(u, "bio");
    out.auth.usesPv = attr(u, "pv");
    out.auth.usesDemo = attr(u, "demo");
  }

  if (auto meta = qp.param("meta")) {
    AttrParser m(*meta);
    out.auth.metaDc = attr(m, "dc");
    out.auth.metaDpId = attr(m, "dpId");
    out.auth.metaMc = attr(m, "mc");
    out.auth.metaMi = attr(m, "mi");
    out.auth.metaRdsId = attr(m, "rdsId");
    out.auth.metaRdsVer = attr(m, "rdsVer");
    out.auth.metaUdc = attr(m, "udc");
    out.auth.metaFdc = attr(m, "fdc");
    out.auth.metaIdc = attr(m, "idc");
    out.auth.metaPip = attr(m, "pip");
    out.auth.metaLot = attr(m, "lot");
    out.auth.metaLov = attr(m, "lov");
  }

  if (auto pi = qp.param("pi")) {
    AttrParser p(*pi);
    out.auth.piMs = attr(p, "ms");
    out.auth.piMv = attr(p, "mv");
    out.auth.piName = attr(p, "name");
    out.auth.piLname = attr(p, "lname");
    out.auth.piLmv = attr(p, "lmv");
    out.auth.piGender = attr(p, "gender");
    out.auth.piDob = attr(p, "dob");
    out.auth.piDobt = attr(p, "dobt");
    out.auth.piAge = attr(p, "age");
    out.auth.piPhone = attr(p, "phone");
    out.auth.piEmail = attr(p, "email");
  }

  if (auto bio = qp.param("bio")) {
    AttrParser b(*bio);
    out.auth.bioType = attr(b, "type");
    out.auth.bioPosh = attr(b, "posh");
    out.auth.bioBs = attr(b, "bs");
    out.auth.bioValue = attr(b, "value");
  }

  if (auto pv = qp.param("pv")) {
    AttrParser v(*pv);
    out.auth.pvPin = attr(v, "pin");
    out.auth.pvOtp = attr(v, "otp");
  }

  if (auto demo = qp.param("demo")) {
    out.auth.demoLang = attr(AttrParser(*demo), "lang");
  }

  if (auto tkn = qp.param("tkn")) {
    AttrParser t(*tkn);
    out.auth.tknType = attr(t, "type");
    out.auth.tknValue = attr(t, "value");
  }
}

void parseOtp(QueryParser& qp, RequestSpec& out) {
  AttrParser o(*qp.param("otp"));
  out.otp.ac = attr(o, "ac");
  out.otp.lk = attr(o, "lk");
  out.otp.sa = attr(o, "sa");
  out.otp.tid = attr(o, "tid");
  out.otp.txn = attr(o, "txn");
  out.otp.type = attr(o, "type");
  out.otp.uid = attr(o, "uid");
  out.otp.ver = attr(o, "ver");

  if (auto opts = qp.param("opts")) {
    out.otp.ch = attr(AttrParser(*opts), "ch");
  }
}

void parseEkyc(QueryParser& qp, RequestSpec& out) {
  AttrParser k(*qp.param("kyc"));
  out.kyc.ver = attr(k, "ver");
  out.kyc.ra = attr(k, "ra");
  out.kyc.rc = attr(k, "rc");
  out.kyc.mec = attr(k, "mec");
  out.kyc.lr = attr(k, "lr");
  out.kyc.de = attr(k, "de");
  out.kyc.pfr = attr(k, "pfr");

  // eKYC resolves its HTTP target from the kyc block (lk/uri), not uidai.uri.
  out.targetLk = attr(k, "lk");
  out.targetUri = attr(k, "uri");

  parseAuth(qp, out);
}

} // namespace

RequestSpec parseRequest(std::string_view line) {
  QueryParser qp(line);

  RequestSpec req;
  auto kind = qp.param("request");
  if (!kind) throw uidai::UidaiError("request kind missing");
  req.kind = std::move(*kind);

  // uidai block: host (always) and uri (otp/auth).
  if (auto uidai = qp.param("uidai")) {
    AttrParser u(*uidai);
    req.host = attr(u, "host");
    req.targetUri = attr(u, "uri");
  }

  // crypto block: AUA p12, UIDAI cer, passphrase.
  if (auto crypto = qp.param("crypto")) {
    AttrParser c(*crypto);
    req.publicKeyFile = attr(c, "public");
    req.privateKeyFile = attr(c, "private");
    req.password = attr(c, "password");
  }

  if (req.kind == "otp") {
    parseOtp(qp, req);
    req.targetLk = req.otp.lk;
  } else if (req.kind == "auth") {
    parseAuth(qp, req);
    req.targetLk = req.auth.lk;
  } else if (req.kind == "ekyc") {
    parseEkyc(qp, req);
  } else {
    throw uidai::UidaiError("unsupported request kind: " + req.kind);
  }

  return req;
}

std::string requestTarget(const RequestSpec& req) {
  const std::string *ac = nullptr;
  const std::string *uid = nullptr;

  if (req.kind == "otp") {
    ac = &req.otp.ac;
    uid = &req.otp.uid;
  } else {
    ac = &req.auth.ac;
    uid = &req.auth.uid;
  }

  if (uid->size() < 2) {
    throw uidai::UidaiError("uid too short for target path");
  }

  // POST http://<host><uri>/<ac>/<uid[0]>/<uid[1]>/<lk>
  std::string target = "http://";
  target += req.host;
  target += req.targetUri;
  target += "/";
  target += *ac;
  target += "/";
  target += (*uid)[0];
  target += "/";
  target += (*uid)[1];
  target += "/";
  target += req.targetLk;
  return target;
}

UidaiClient::UidaiClient(TransportFactory factory) : factory_(std::move(factory)) {
  if (!factory_) {
    factory_ = [](const std::string& host, unsigned short port) {
      return std::make_unique<transport::LibeventTransport>(host, port);
    };
  }
}

std::string UidaiClient::handle(const RequestSpec& req) {
  using uidai::crypto::CryptoEngine;
  using uidai::crypto::KeyStore;

  KeyStore ks = KeyStore::load(req.privateKeyFile, req.password, req.publicKeyFile);

  const std::string ts = authTimestamp();
  std::string body;

  if (req.kind == "otp") {
    if (startsWith(req.otp.ver, "1.6")) {
      body = otpSignXmlV16(req.otp, ts, ks);
    } else {
      body = otpSignXmlV25(req.otp, ts, ks);
    }
  } else if (req.kind == "auth") {
    const auto sk = CryptoEngine::randomSessionKey();
    if (startsWith(req.auth.ver, "1.6")) {
      body = authSignXmlV16(req.auth, ts, sk, ks);
    } else if (startsWith(req.auth.ver, "2.0")) {
      body = authSignXmlV20(req.auth, ts, sk, ks);
    } else {
      body = authSignXmlV25(req.auth, ts, sk, ks);
    }
  } else if (req.kind == "ekyc") {
    const auto sk = CryptoEngine::randomSessionKey();
    std::string authXml;
    if (startsWith(req.auth.ver, "1.6")) {
      authXml = authSignXmlV16(req.auth, ts, sk, ks);
    } else if (startsWith(req.auth.ver, "2.0")) {
      authXml = authSignXmlV20(req.auth, ts, sk, ks);
    } else {
      authXml = authSignXmlV25(req.auth, ts, sk, ks);
    }
    body = ekycComposeXml(authXml, req.kyc, ts);
  } else {
    throw uidai::UidaiError("unsupported request kind: " + req.kind);
  }

  transport::HttpRequest http;
  http.method = "POST";
  http.target = requestTarget(req);
  http.version = "HTTP/1.1";
  http.headers = {
      {"Host", req.host},
      {"Content-Type", "text/xml"},
      {"Connection", "Keep-alive"},
      {"Content-Length", std::to_string(body.size())},
  };
  http.body = std::move(body);

  auto transport = factory_(req.host, 80);
  transport::HttpResponse rsp = transport->perform(http);

  return uidai::core::formatDisplayResponse(uidai::core::parseResponseXml(rsp.body));
}

} // namespace uidai::protocol
