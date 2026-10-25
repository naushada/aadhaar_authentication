# UIDAI Client — C++ Port Design Specification

> Port of `uidai/` (the C AUA/ASA client) to C++17 with **libevent** for the
> socket/event interface.
>
> Scope of this document: architecture + module design only. No code is
> scaffolded yet. Companion to the original sources in `uidai/{staging,production,preproduction}/src`.

---

## 1. Goals

1. **Faithful port** — reproduce the exact wire bytes (XML, canonicalization,
   signatures, ciphertext layout) of the current C client. UIDAI is strict about
   byte-exact canonicalization and signature digests.
2. **Replace the fragile parts** — the hand-rolled base64, `sscanf`-based
   parsing, fixed-size buffers, and scattered `malloc`/`free` become
   `std::string`/`std::vector` + RAII. Same output, safer code.
3. **Version matrix made explicit** — OTP 1.6/2.5, Auth 1.6/2.0/2.5, eKYC
   2.0/2.1/2.5 are first-class strategies instead of `if (version == 16) …`
   sprinkled through `auth.c`.
4. **libevent as the socket layer** — one `event_base`, `bufferevent`-based
   connections, chunked decoding, timeouts; replacing the `select` + `MSG_PEEK`
   polling loops.
5. **Keep porting simple** — a direct 1:1 C→C++ mapping table (Section 10) so
   each original function has an obvious destination.

### Non-goals (this phase)

- No TLS yet (the C client sends plaintext HTTP; see Risks §17.2).
- No GUI port (Tcl/Tk stays as-is until M7 of the roadmap).
- No new features; byte-for-byte compatibility first.

---

## 2. Guiding principles ("keep porting simple")

1. **One class ≈ one C file's responsibility**, one method ≈ one C function.
   Preserve the original function names as `snake_case` comments.
2. **Don't "improve" the protocol.** Keep the exact string literals used for
   canonicalization and XML templates. If the C code produces a specific
   (even odd) byte, the C++ must produce the identical byte.
3. **RAII replaces `assert(NULL)`-on-`malloc`.** OpenSSL handles
   (`EVP_CIPHER_CTX*`, `BIO*`, `X509*`, `RSA*`, `EVP_PKEY*`, `PKCS12*`) get
   `unique_ptr` deleters. No bare `free`.
4. **No heavy XML library.** The C client hand-composes XML with `snprintf`.
   A tiny `XmlBuilder` (§6.4) is enough and keeps the canonicalized strings
   byte-identical. No libxml2/tinyxml dependency.
5. **Single-threaded event loop.** All crypto + I/O on the libevent thread.
   No locks, no threads. (See §12.)
6. **Golden-file regression** from day one — the sample files already in the
   repo root (`auth_success.xml`, `otp_success.xml`, `auth_response.xml`, …)
   are the acceptance criteria.

---

## 3. Technology choices

| Concern | Choice | Why |
|---|---|---|
| Language | C++17 | `std::string_view`, `std::optional`, structured bindings; broad compiler support |
| Event loop / sockets | **libevent 2.1+** (`event_base`, `bufferevent`) | User-selected; replaces `select`/`gethostbyname`/`recv(MSG_PEEK)` |
| Crypto | OpenSSL (EVP APIs already used) | Same primitives as today: AES-256-GCM, SHA-1/SHA-256, RSA, PKCS#12, X509 |
| Build | CMake 3.16+ | `find_package(Libevent)`, `find_package(OpenSSL)`; replaces autotools |
| Testing | Catch2 (or GTest) + golden files | Unit tests per module, byte-compare against captured XML |
| Logging | Small `Logger` wrapper over stderr/syslog | Parity with the `fprintf(stderr, …)` traces |

> **OpenSSL note:** the C Makefile pins `/usr/local/openssl-1.1.0e`. The port
> should build against **1.1.1 or 3.x** and use only the EVP high-level APIs
> (already the case). Two calls to watch on 3.x: `RSA_public_encrypt` /
> `RSA_private_decrypt` (deprecated — wrap them in one `RsaPkcs1` helper so the
> change is localized) and SHA-1 (allowed via the EVP digest interface).

---

## 4. Design patterns

| Pattern | Where | Purpose |
|---|---|---|
| **Facade** | `UidaiClient` (top level), `OtpClient`/`AuthClient`/`EkycClient` | One call = full request→response; hides crypto+xml+transport |
| **Builder** | `XmlBuilder` + per-protocol builders | Compose XML incrementally, eliminating the fragile `snprintf` format-string chains |
| **Strategy** | `IOtpStrategy`, `IAuthStrategy`, `IEkycStrategy` per version | Encapsulate the 1.6/2.0/2.1/2.5 differences in one place |
| **Abstract Factory + Registry** | `ProtocolFactory` | Maps `(RequestKind, Version)` → strategy; adding a version = one registration |
| **Adapter** | `HttpTransport` (interface) + `LibeventTransport` (impl) | Decouple protocol logic from libevent; enables a mock transport in tests |
| **RAII / Pimpl** | `CryptoEngine`, `KeyStore`, all OpenSSL wrappers | Ownership-safety; hide OpenSSL types from headers |
| **State machine** | `ChunkedDecoder` | Clean incremental HTTP `Transfer-Encoding: chunked` reader |

**Why Strategy + Factory is the core decision.** The version matrix is the main
source of complexity in the C code. Isolating it behind `(kind, version) →
strategy` means:

- a new UIDAI spec version touches **one new file + one registry line**;
- `UidaiClient` never knows which version it is running;
- each strategy is independently unit-testable against a golden file.

---

## 5. Package layout (proposed)

```
cpp/
├── DESIGN.md                  ← this document
├── CMakeLists.txt             (M0)
├── include/uidai/
│   ├── core/
│   │   ├── config.h           Config, Credentials
│   │   ├── types.h            RequestKind, Version, Response, UidaiError
│   │   └── logger.h
│   ├── crypto/
│   │   ├── crypto_engine.h    facade: AES-GCM, SHA, RSA, base64
│   │   ├── key_store.h        PKCS#12 + X509 loading, subject/cert extraction
│   │   └── detail/            RAII deleters (evp_ctx.h, bio.h, x509.h, …)
│   ├── xml/
│   │   ├── xml_builder.h      incremental tag/attr/esc composition
│   │   └── xml_signature.h    enveloped XML-DSig (SignedInfo/SignatureValue/KeyInfo)
│   ├── transport/
│   │   ├── http_transport.h   abstract post() → Future<Response>
│   │   ├── libevent_transport.h
│   │   ├── event_loop.h       owns event_base; dispatch()
│   │   ├── chunked_decoder.h  state machine
│   │   └── http.h             HttpRequest / HttpResponse value types
│   ├── protocol/
│   │   ├── strategy.h         base strategy interfaces
│   │   ├── otp/               otp_client.h + otp_v16/v25 strategies
│   │   ├── auth/              auth_client.h + auth_v16/v20/v25 strategies
│   │   ├── ekyc/              ekyc_client.h + ekyc_v20/v21/v25 strategies
│   │   └── protocol_factory.h
│   └── uidai_client.h         facade
└── src/                       mirrors include/uidai/ (one .cpp per header)
```

---

## 6. Class design

### 6.1 Core types (`core/`)

```cpp
enum class RequestKind { Otp, Auth, Ekyc };
enum class Version   { V16, V20, V21, V25 };   // + fromString("1.6") helpers

struct Credentials {
  std::string ac;        // AUA code (currently "public")
  std::string sa;        // Sub-AUA
  std::string lk;        // ASA license key
  std::string password;  // PKCS#12 password (currently "public")
  std::string tid;       // "public" or "registered"
  std::string txnPrefix; // "SampleClient" / "TXN:BalaaghTesting"
};

struct Config {
  Credentials creds;
  std::string host;      // developer.uidai.gov.in
  std::string uri;       // "/auth", "/otp", "/kyc" prefix
  std::string publicKeyFile;   // .cer
  std::string privateKeyFile;  // .p12
};

struct Response {
  bool   ok;             // ret == "y"
  std::string ret, code, err, actn, info, txn, ts;
  std::string rawBody;   // keep for debugging/golden compare
};
```

`UidaiError` is the exception base (subtypes: `CryptoError`, `TransportError`,
`ParseError`). Business failures (UIDAI `ret="n"`) are **not** exceptions — they
are a populated `Response` with `ok == false`.

### 6.2 Crypto (`crypto/`)

```cpp
class CryptoEngine {
public:
  // ported from auth_cipher_gcm / auth_decipher
  std::string aes256GcmEncrypt(span<const uint8_t> plain,
                               span<const uint8_t> iv,   // 12 bytes
                               span<const uint8_t> aad,  // 16 bytes
                               std::array<uint8_t,16>& tag) const;

  // ported from util_compute_digest (SHA-1) and auth_hmac (SHA-256)
  std::string sha1(span<const uint8_t> data) const;
  std::string sha256(span<const uint8_t> data) const;

  // ported from auth_skey / util_decrypt_skey (RSA_PKCS1_PADDING)
  std::string rsaPublicEncrypt(span<const uint8_t> data) const;
  std::string rsaPrivateDecrypt(span<const uint8_t> data) const;

  // ported from util_compute_rsa_signature (rsa-sha1)
  std::string rsaSha1Sign(span<const uint8_t> canonicalizedSignedInfo) const;

  // base64: replace the hand-rolled util_base64[_decode] with OpenSSL EVP
  std::string base64Encode(span<const uint8_t> data) const;
  std::string base64Decode(std::string_view b64) const;
};

class KeyStore {
public:
  static KeyStore load(const Config&);   // opens .p12 (password) + .cer
  std::string subjectName() const;       // "C=IN,ST=KA,…" comma form
  std::string certificateB64() const;    // PEM body, newlines stripped
  std::string publicKeyPemPath() const;
private:
  class Impl; std::unique_ptr<Impl> p_;  // hides X509*/RSA*/EVP_PKEY*
};
```

> **Important porting rule:** `util_subject_certificate` strips the PEM armor by
> hand and rewrites the subject from `/`-separated to `,`-separated. Reproduce
> that transformation **exactly** (including the trailing-comma behaviour) or the
> `X509SubjectName` in the signed XML changes and UIDAI rejects the signature.

### 6.3 Session key + PID (Auth-specific helpers)

Kept in `auth/` strategies rather than `CryptoEngine` because they encode UIDAI
policy:

- `makeSessionKey()` — 32 bytes from `std::random_device`/`/dev/urandom`
  (ported from `auth_symmetric_keys`).
- `deriveIvAad(ts)` — IV = last 12 bytes of `ts`, AAD = last 16 bytes
  (ported from `auth_compute_ts`).
- `hmacV20(pid)` — `sha256(pid)` then **AES-256-GCM encrypt that 32-byte digest**
  with `is_hmac=true` (no ts prepended) — the non-standard UIDAI "HMAC"
  (ported from `auth_hmac`). Must not be "fixed" to a real HMAC.
- `skey()` — `rsaPublicEncrypt(sessionKey)` wrapped in `<Skey ci="{expiry}">`
  (ported from `auth_skey`, including the `notAfter` month-name → index mapping).

### 6.4 XML (`xml/`)

```cpp
class XmlBuilder {
public:
  XmlBuilder& decl();                              // <?xml …?>
  XmlBuilder& open(std::string_view tag);          // <tag>
  XmlBuilder& open(std::string_view tag, const std::map<std::string,std::string>& attrs);
  XmlBuilder& attr(std::string_view k, std::string_view v);
  XmlBuilder& selfClose(std::string_view tag, const std::map<…>& attrs); // <tag …/>
  XmlBuilder& text(std::string_view t);            // (no auto-escape: UIDAI content is pre-encoded)
  XmlBuilder& close(std::string_view tag);         // </tag>
  std::string str() const;
};
```

`XmlSignature::envelopedSignature(digestB64, sigB64, subject, certB64)` ports
`util_c14n_signedinfo` + `util_compose_final_xml`. Keep the whitespace
(newlines/indentation) **identical** to the current output.

### 6.5 Transport (`transport/`)

```cpp
class HttpTransport {
public:
  virtual ~HttpTransport() = default;
  // async; resolves when the full (possibly chunked) body has arrived
  virtual std::future<Response> post(const HttpRequest&) = 0;
};

class HttpRequest {
  std::string method = "POST";
  std::string host;                 // developer.uidai.gov.in
  std::string target;               // /otp/1.6/public/9/7/{lk}
  std::string body;                 // the signed XML
};

class EventLoop {
public:
  void dispatch();                  // event_base_dispatch()
  void stop();
  event_base* base();               // exposed only to LibeventTransport
private:
  class Impl; std::unique_ptr<Impl> p_;
};

class LibeventTransport : public HttpTransport {
  explicit LibeventTransport(EventLoop&);
  std::future<Response> post(const HttpRequest&) override;
};
```

`ChunkedDecoder` is a pure state machine (`std::string feed(std::string_view)` /
`bool done()`) that replaces `uidai_pre_process_uidai_rsp`'s peek-until-zero
loop and `uidai_process_uidai_rsp`'s `strtok_r` body extraction.

### 6.6 Protocol strategies (`protocol/`)

```cpp
// protocol/strategy.h
class IRequestStrategy {
public:
  virtual ~IRequestStrategy() = default;
  virtual HttpRequest compose(const Params&) const = 0;   // signed XML → HttpRequest
  virtual Response   parse(HttpResponse) const = 0;        // raw → Response
};
```

Each module gets a **client facade** + one strategy per version:

- `OtpClient` → `OtpV16Strategy`, `OtpV25Strategy`
- `AuthClient` → `AuthV16Strategy`, `AuthV20Strategy`, `AuthV25Strategy`
- `EkycClient` → `EkycV20Strategy`, `EkycV21Strategy`, `EkycV25Strategy`

`Ekyc*Strategy` **composes an `AuthClient` internally** (it wraps a signed
`<Auth>` XML, base64-encodes it, and places it in `<Kyc><Rad>…</Rad></Kyc>`),
mirroring the C `auth_process_ekyc_req` path — this dependency is why `auth/`
is required even though the user-facing modules are OTP and eKYC.

`ProtocolFactory`:

```cpp
class ProtocolFactory {
public:
  void registerStrategy(RequestKind, Version, std::unique_ptr<IRequestStrategy>);
  const IRequestStrategy& get(RequestKind, Version) const;   // throws UidaiError if absent
};
```

### 6.7 Facade (`UidaiClient`)

```cpp
class UidaiClient {
public:
  UidaiClient(Config, EventLoop&, ProtocolFactory);   // builds KeyStore, CryptoEngine, transport
  Response otp(std::string_view uid, const OtpParams&);
  Response auth(std::string_view uid, const AuthParams&);
  Response ekyc(std::string_view uid, const KycParams&);
private:
  class Impl; std::unique_ptr<Impl> p_;
};
```

`Params` types (`OtpParams`, `AuthParams`, `KycParams`) carry the GUI form
fields (the `{uid=…,name=…,ms=…}` blocks) as structured values instead of
the current nested `key=value` string blob.

---

## 7. libevent socket design

### 7.1 Event loop ownership

- One `EventLoop` per process (singleton held by `UidaiClient`), running the
  libevent reactor on the **main thread**.
- The GUI pipe (from the C `main()` / `uidai_process_gui_req`) is registered as
  a libevent `event` (EV_READ | EV_PERSIST) on the pipe read-end. This unifies
  the two current loops (`uidai_main`'s `select` loop and the GUI pipe loop)
  into one reactor.
- Optional daemon mode: register the `listen` socket's accept via
  `event`/`bufferevent` accept, retaining the current ACC/NAS → daemon flow.

### 7.2 Connection lifecycle (per request)

1. `bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS)`.
2. `bufferevent_setcb(bev, onRead, nullptr, onEvent, this)`.
3. `bufferevent_socket_connect_hostname(bev, nullptr, AF_INET, host, port)`
   — replaces `gethostbyname` + `inet_addr` + `connect`.
4. `bufferevent_set_timeouts(bev, connectTimeout, ioTimeout)` — replaces the
   `select`/`timeval` waits in `uidai_chunked_rsp`.
5. On connect (`BEV_EVENT_CONNECTED`), `bufferevent_write(bev, request.bytes())`.
6. `onRead` drains into `ChunkedDecoder`; when `done()`, resolve the
   `std::promise` with the parsed `Response`.
7. `onEvent` (EOF/error/timeout) resolves the promise with `TransportError`.

Each `post()` allocates a small per-request state (`std::shared_ptr<RequestState>`)
holding the `promise`, decoder, and request echo — freed by `BEV_OPT_CLOSE_ON_FREE`.

### 7.3 Why not `evhttp`

`evhttp` could carry the HTTP layer, but UIDAI's responses are `chunked` XML
over a keep-alive connection and the existing framing is minimal. `bufferevent`
keeps the port 1:1 with the current `uidai_send`/`uidai_recv`/`uidai_pre_process_uidai_rsp`
code and avoids fighting `evhttp`'s buffering. (`evhttp` remains a viable
alternative noted in §17.3.)

---

## 8. Data flow

### 8.1 OTP (v1.6)

```
GUI pipe ──event──▶ RequestParser ──▶ UidaiClient::otp()
  │
  ├─ OtpV16Strategy::compose()
  │     ├─ XmlBuilder  → <Otp …><Opts ch="01"/></Otp>   (otp_compose_otp_v16)
  │     ├─ XmlSignature→ sha1(c14n) → rsa-sha1 sign     (otp_sign_xml_v16)
  │     └─ HttpRequest::fromBody("POST /otp/1.6/{ac}/{u0}/{u1}/{lk}")
  │
  ├─ LibeventTransport::post()  (bufferevent → chunked)
  │     └─ ChunkedDecoder → <OtpRes ret code info txn ts>
  │
  └─ OtpV16Strategy::parse() → Response{ok, code, info, …}
```

### 8.2 Auth (v2.0) — the crypto-heavy path

```
UidaiClient::auth()
  ├─ AuthV20Strategy::compose()
  │     ├─ makeSessionKey()  (32B random)
  │     ├─ composePid()      → <Pid ts ver><Pv otp/pin/…></Pid>  (auth_compose_pid_v20)
  │     ├─ CryptoEngine::aes256GcmEncrypt(pid, iv, aad) → <Data type="X">b64</Data>
  │     ├─ hmacV20(pid)       → <Hmac>b64</Hmac>
  │     ├─ CryptoEngine::rsaPublicEncrypt(skey) → <Skey ci="…">b64</Skey>
  │     ├─ XmlSignature       → enveloped rsa-sha1 <Signature>…
  │     └─ HttpRequest::fromBody("POST /auth/2.0/{ac}/{u0}/{u1}/{lk}")
  └─ (transport/parse as OTP)
```

### 8.3 eKYC

```
UidaiClient::ekyc()
  └─ EkycV20Strategy::compose()
        ├─ AuthClient::auth(…)        ← full signed <Auth>…</Auth> XML
        ├─ CryptoEngine::base64Encode(authXml)
        └─ XmlBuilder → <Kyc ver ra rc lr de pfr><Rad>{b64}</Rad></Kyc>
        └─ HttpRequest::fromBody("POST /kyc/…")
```

---

## 9. Request/response parsing

The current parser splits a single line like
`/request?stage=staging&request=auth&auth={uid=…,ac=…}&uses={pi=1,…}` and the
nested `{k=v,…}` attributes. Replace with two small, table-driven parsers in
`core/` (no external dependency):

- `QueryParser` — `uidai_get_param` / `uidai_get_rparam` (top-level `&`-separated).
- `AttrParser` — `uidai_get_attr` (comma-separated `k=v` inside `{…}`).

The response path (`uidai_parse_rsp`) maps `ret/err/code/actn/info` into the
`response_display_response …` line — port verbatim to `ResponseParser`, but
return a `Response` struct instead of a space-joined string.

---

## 10. C → C++ mapping table

| Original C (staging) | C++ destination |
|---|---|
| `otp_get_ts`, `auth_compute_ts`, `auth_get_ts` | `core::Timestamp::nowIso8601()` + `deriveIvAad()` in auth strategy |
| `otp_compose_otp_v16/_v25`, `otp_compose_c14n_v16/_v25` | `OtpV16Strategy::compose()`, `OtpV25Strategy::compose()` |
| `otp_sign_xml_v16/_v25` | `xml::XmlSignature` (driven by OTP strategy) |
| `otp_compose_http_request` | `transport::HttpRequest::fromBody()` |
| `otp_main_ex*` | `OtpClient::request()` |
| `auth_init_ex` | `Config` + `KeyStore::load()` |
| `auth_compose_pid_*_v16/v20/v25` | `AuthVxxStrategy::composePid()` |
| `auth_compose_uses/meta/tkn_tag_*` | strategy + `xml::XmlBuilder` |
| `auth_cipher_gcm` / `auth_decipher` | `crypto::CryptoEngine::aes256GcmEncrypt/Decrypt()` |
| `auth_hmac_v20` | `AuthV20Strategy::hmacV20()` |
| `auth_skey` / `auth_symmetric_keys` | `crypto::CryptoEngine::rsaPublicEncrypt()` + strategy `makeSessionKey()` |
| `auth_c14n_auth_xml` / `auth_compose_xml` | strategy `compose()` via `XmlBuilder` |
| `auth_c14n_sign` | `xml::XmlSignature::envelopedSignature()` |
| `auth_compose_http_req` / `auth_req_auth` | `transport::HttpRequest::fromBody()` |
| `auth_main_ex*` | `AuthClient::request()` |
| `ekyc_compose_xml_v20/v21/v25` | `EkycVxxStrategy::compose()` |
| `ekyc_compose_http_req` | `transport::HttpRequest::fromBody()` |
| `ekyc_main_ex*` | `EkycClient::request()` |
| `util_base64` / `util_base64_decode[_ex]` | `crypto::CryptoEngine::base64Encode/Decode()` (OpenSSL EVP) |
| `util_compute_digest` | `crypto::CryptoEngine::sha1()` |
| `util_compute_rsa_signature` | `crypto::CryptoEngine::rsaSha1Sign()` |
| `util_subject_certificate` | `crypto::KeyStore::subjectName()/certificateB64()` |
| `util_c14n_signedinfo` / `util_compose_final_xml` | `xml::XmlSignature` |
| `util_decrypt_skey` | `crypto::CryptoEngine::rsaPrivateDecrypt()` |
| `uidai_connect_uidai` | `transport::LibeventTransport` (bufferevent connect) |
| `uidai_send` / `uidai_recv` | `bufferevent` write/read |
| `uidai_pre_process_uidai_rsp` / `uidai_process_uidai_rsp` | `transport::ChunkedDecoder` |
| `uidai_parse_req` | `core::QueryParser` + `UidaiClient` dispatch |
| `uidai_parse_rsp` / `uidai_get_rsp_param` | `core::ResponseParser` |
| `uidai_get_param/_rparam` / `uidai_get_attr` | `core::QueryParser` / `core::AttrParser` |
| `uidai_spawn_gui` / `uidai_process_gui_req` / `main` | `EventLoop` + a `GuiPipeSource` registered on the loop (M7) |

---

## 11. Error handling

- **Local failures** (bad config, crypto, socket, parse) → throw `UidaiError`
  subclasses. These are programming/environment faults, not business outcomes.
- **UIDAI business outcomes** (`ret="n"`, `err`, `actn`) → `Response{ok=false}`
  with `err`/`actn` populated; caller decides (matches the C code's
  `status=failed&reason=…` handling).
- No `assert()` in the ported library code; use exceptions + `std::optional`
  for absent values.

---

## 12. Threading model

- **Single-threaded.** The libevent reactor, crypto, and XML building all run on
  the main thread. This matches the current client's concurrency (it is
  effectively serial) and avoids locking entirely.
- `std::future` is used **only** as a completion handshake between the
  synchronous `UidaiClient` API and the async `bufferevent` callbacks — it does
  **not** imply a background thread (the future is resolved inside the event
  callback on the same thread; the caller may `get()` it after `dispatch()`
  yields, or the facade may expose a callback instead).
- If concurrency is ever needed, add a worker pool **behind** `HttpTransport`
  (the Adapter seam already isolates it).

---

## 13. Build system

```cmake
cmake_minimum_required(VERSION 3.16)
project(uidai_cpp CXX)
set(CMAKE_CXX_STANDARD 17)

find_package(OpenSSL REQUIRED)    # libcrypto + libssl
find_package(Libevent REQUIRED)   # libevent_core

add_library(uidai_core STATIC …)      # core + crypto + xml
add_library(uidai_transport STATIC …) # links Libevent::core
add_library(uidai_protocol STATIC …)  # otp/auth/ekyc
add_executable(uidai_cli src/cli.cpp) # thin CLI/driver for manual testing
```

The `cli` executable initially reproduces the GUI-pipe line protocol so the
existing Tcl/Tk GUI can be pointed at it unchanged during migration.

---

## 14. Testing strategy

1. **Golden files.** Repo root already holds `auth_success.xml`, `auth20_success.xml`,
   `auth25_success.xml`, `otp_success.xml`, `otp_failure.xml`, `auth_response.xml`,
   `otp.xml`. Byte-compare `CryptoEngine`/`XmlSignature`/strategy output against
   these (timestamp/`ts` fields normalized). This is the highest-value test set.
2. **Round-trip tests.** `aes256GcmEncrypt → Decrypt`, `rsaPublicEncrypt →
   rsaPrivateDecrypt`, `base64Encode → Decode`.
3. **Parser tests.** `QueryParser`/`AttrParser`/`ResponseParser` against captured
   request/response lines.
4. **Transport tests.** `LibeventTransport` against a local `netcat`-style mock
   HTTP server that returns chunked responses (and edge cases: split chunks,
   timeout, connection close mid-body).
5. **Strategy tests.** One golden test per `(kind, version)` pair.

---

## 15. Test-driven development per milestone

Adopt **test-first** discipline, scoped to where it pays off. For a port the
*specification already exists* — the C source and the golden XML files in the
repo root. TDD here means: **write the byte-assertion first, watch it fail,
then implement**, using the golden files as the oracle.

**Where TDD applies (pure functions — strict red/green/refactor):**

- `crypto/*` — base64, SHA-1/256, AES-GCM encrypt/decrypt, RSA sign/encrypt/decrypt.
- `xml/*` — `XmlBuilder` + `XmlSignature` (assert exact bytes incl. whitespace).
- `core/*` parsers — `QueryParser`, `AttrParser`, `ResponseParser` (feed captured lines, assert fields).
- `protocol/*` strategies — one golden test per `(kind, version)` pair.
- `transport/ChunkedDecoder` — pure state machine; feed byte slices, assert framing.

**Where TDD does not apply (infrastructure/integration):**

- **M0** build scaffolding — exit criterion is "configures + builds clean", not a unit test.
- **M7** GUI integration — exit criterion is a smoke test against the real Tcl/Tk GUI.
- `LibeventTransport` callbacks — async/event-driven; cover with **contract tests**
  against a mock chunked HTTP server rather than unit-first TDD.

**Per-milestone red → green plan:**

| Milestone | Failing test written first ("red") | Makes it pass ("green") |
|---|---|---|
| M1 | base64/SHA/RSA/signature byte-equal golden vectors | implement `CryptoEngine`, `XmlSignature` |
| M2 | `ChunkedDecoder` frames a captured chunked response; mock-server contract tests | implement decoder + `LibeventTransport` |
| M3 | `otp_success.xml` reproduced (ts-normalized) | implement `OtpV16Strategy` + `OtpClient` |
| M4 | `auth20_success.xml` reproduced | implement `AuthV20Strategy` |
| M5 | `<Kyc><Rad>{b64(Auth)}</Rad></Kyc>` matches fixture | implement `EkycV20/21/25` |
| M6 | remaining version golden tests (OTP 2.5, Auth 1.6/2.5) | remaining strategies |
| M0/M7 | build succeeds / GUI smoke test | scaffolding / pipe source |

**Rules:**

1. A milestone is done only when its golden test passes **and** no prior golden
   test regresses.
2. Normalize volatile fields (`ts`, `txn`, random session key, `Skey ci` expiry)
   before comparing — compare structure + fixed bytes, not nonces.
3. Keep the C binary buildable in parallel so its output remains the reference
   oracle whenever a fixture is ambiguous.

---

## 16. Migration roadmap

| Milestone | Scope | Exit criterion |
|---|---|---|
| **M0** | CMake + empty libs, link OpenSSL+libevent, `Logger` | project configures/builds clean |
| **M1** | `core` + `crypto` + `xml` (port `util.c`) | golden-file tests pass for base64/SHA/RSA/signature/XML |
| **M2** | `transport` (libevent + `ChunkedDecoder`) | chunked mock-server tests pass |
| **M3** | `otp` v1.6 end-to-end | `otp_success.xml` reproduced; staging call succeeds |
| **M4** | `auth` v2.0 (full crypto) | `auth20_success.xml` reproduced |
| **M5** | `ekyc` (v2.0 first, then 2.1/2.5) | `<Kyc><Rad>` wraps signed Auth correctly |
| **M6** | remaining strategies (OTP 2.5, Auth 1.6/2.5) | full version matrix green |
| **M7** | GUI pipe source + `uidai_cli` driver | existing Tcl/Tk GUI works against the C++ binary |

Each milestone is independently shippable; M3 is the first vertical slice.

---

## 17. Risks & open questions

1. **Byte-exact canonicalization** — the biggest risk. The C code hand-rolls C14N
   and signature strings; any whitespace drift changes the digest. Mitigation:
   golden-file tests from M1, and keep the original string literals verbatim.
2. **TLS.** The C client sends plaintext HTTP; UIDAI's staging endpoint accepted
   this historically but production is HTTPS. Decision needed: (a) keep
   plaintext for parity, or (b) use libevent's `bufferevent_openssl` to add TLS.
   Recommend (b) behind a config flag, default off for parity.
3. **`evhttp` vs `bufferevent`** — this spec chooses `bufferevent` for parity;
   revisit if header/framing handling grows.
4. **OpenSSL version** — pin to 1.1.1 or 3.x and centralize the two deprecated
   RSA calls. Confirm UIDAI accepts the same signatures from 3.x (they should;
   RSA-SHA1 + AES-GCM are version-agnostic).
5. **`auth_hmac` non-standard construction** — must be reproduced, not
   "corrected", or every Auth request will be rejected.
6. **Hardcoded credentials** — the demo `public`/`public` AUA and `lk` should
   move into `Config` (loaded from a file/env), not be compiled in.

---

## 18. Open decisions for the reader

- Exact namespace: `uidai::` (proposed) vs `uidai::cpp` vs no namespace.
- Error-propagation preference: exceptions (proposed) vs `std::expected` if the
  team targets C++23 later.
- Whether the CLI driver should speak the old GUI pipe protocol or a cleaner
  JSON/argv interface.
