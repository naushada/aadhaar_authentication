# Cryptography in the C++ port

This documents how the client encrypts and signs the UIDAI requests. It maps
each step to the function that performs it, so you can trace a byte end-to-end.

The client is the AUA/ASA side: it **encrypts** the resident's data so only
UIDAI can read it, and **signs** the request so UIDAI can verify who sent it.
UIDAI does the reverse — decrypt and verify — on the server. The client-side
decryption/verification primitives exist (see *Client-side decryption* below)
but are not exercised by the request path.

---

## 1. The primitives — `CryptoEngine`

Stateless OpenSSL wrappers in `src/crypto/crypto_engine.cpp` (declared in
`include/uidai/crypto/crypto_engine.h`). Every one throws `UidaiError` on
failure.

| Primitive | Cipher / scheme | Used for |
|-----------|-----------------|----------|
| `sha1` / `sha256` | SHA-1 / SHA-256 | signature digest, Hmac |
| `base64Encode` / `base64Decode` | RFC 4648, **no line breaks** | all wire base64 |
| `randomSessionKey` | 32 bytes from `RAND_bytes` | per-request session key |
| `aes256GcmEncrypt` | AES-256-GCM, key 32 / IV 12 / AAD 16, tag appended | Auth v2.0/v2.5 `<Data>`/`<Hmac>` |
| `aes256GcmDecrypt` | same, tag checked on finalize | (server side / tests) |
| `aes256EcbEncrypt` | AES-256-ECB, PKCS#7 padding | Auth v1.6 `<Data>`/`<Hmac>` |
| `aes256EcbDecrypt` | same, padding verified | (server side / tests) |
| `rsaPublicEncrypt` | RSA PKCS#1 v1.5 | wrap the session key (`<Skey>`) |
| `rsaPrivateDecrypt` | RSA PKCS#1 v1.5 | (server side / tests) |
| `rsaSha1Sign` | RSA + SHA-1 (PKCS#1 v1.5) | XML-DSig `<SignatureValue>` |
| `rsaSha1Verify` | RSA + SHA-1 verify | (server side / tests) |

### GCM layout (`aes256GcmEncrypt`)

Output is `ciphertext || tag`, where `tag` is the 16-byte authentication tag
read back with `EVP_CTRL_GCM_GET_TAG`. The plaintext length is unchanged; the
caller appends/prepends whatever framing the protocol wants.

---

## 2. Key material — `KeyStore`

Loaded once per request in `KeyStore::load(p12Path, password, cerPath)`
(`src/crypto/key_store.cpp`):

1. **AUA private key + certificate** come from a PKCS#12 bundle
   (`Staging_Signature_PrivateKey.p12`, password `public`). On OpenSSL 3.x the
   legacy provider is loaded first, because UIDAI's 2017-era PKCS#12 uses
   RC2/3DES.
2. **UIDAI public key** comes from a PEM `.cer` (`uidai_auth_stage.cer`).

Three keys are then available:

| Accessor | What it is | Used for |
|----------|-----------|----------|
| `privateKey()` | AUA private key | `rsaSha1Sign` |
| `publicKey()` | UIDAI public key | `rsaPublicEncrypt` (wrap session key) |
| `signingPublicKey()` | AUA cert's public key | verification (not in request path) |

`KeyStore` also yields the strings that go into the signature block:
`subjectName()`, `certificateB64()`, and `publicCertExpiryYYYYMMDD()` (the
`<Skey ci="…">` attribute).

---

## 3. Auth v2.0 / v2.5 — the full flow

Entry point `authSignXmlV20` / `authSignXmlV25` in `src/protocol/auth.cpp`
(both share `signAuth`; only the `<Meta>` tag differs).

### Step A — timestamp and GCM parameters

```
ts  = authTimestamp()            // "YYYY-MM-DDTHH:MM:SS" (local time)
iv  = last 12 bytes of ts        // authCryptoContext()
aad = last 16 bytes of ts
```

UIDAI quirk: the timestamp suffix *is* the GCM IV/AAD — there is no random IV.
This is intentional on their side and must be reproduced byte-exactly.

### Step B — session key and its wrap (`<Skey>`)

```
sessionKey = randomSessionKey()                    // 32 random bytes
skeyCipher = rsaPublicEncrypt(UIDAI_public, sessionKey)
Skey       = <Skey ci="YYYYMMDD">base64(skeyCipher)</Skey>
```

`authComposeSkey()`. Only UIDAI's private key can recover the session key. `ci`
is the UIDAI cert's `notAfter` formatted `YYYYMMDD`.

### Step C — encrypt the resident data (`<Data>`)

```
pidXml  = <Pid …>…</Pid>                            // demographic/bio/otp data
ct      = aes256GcmEncrypt(sessionKey, iv, aad, pidXml)   // ciphertext || tag
Data    = <Data type="X">base64( ts || ct )</Data>
```

`authComposeDataV20()`. Note the plaintext `ts` (19 bytes) is prepended to the
GCM ciphertext before base64 — the server uses it to re-derive IV/AAD.

### Step D — integrity (`<Hmac>`)

```
digest = sha256(pidXml)
hmac   = <Hmac>base64( aes256GcmEncrypt(sessionKey, iv, aad, digest) )</Hmac>
```

`authComposeHmacV20()`. The SHA-256 of the Pid XML is itself GCM-encrypted with
the same key/IV/AAD.

### Step E — XML-DSig signature

```
c14n      = canonical <Auth> string (closed-form <Uses>/<Meta>, plus Skey/Hmac/Data)
digest    = sha1(c14n)
digestB64 = base64(digest)
signedInfo = c14nSignedInfo(digestB64)              // canonical <SignedInfo>
sig        = rsaSha1Sign(AUA_private, signedInfo)
sigB64     = base64(sig)
```

The final document is the non-canonical `<Auth>` (self-closing `<Uses/>`,
`<Meta/>`) plus the `<Signature>` block from `composeSignatureBlock()`. This
"canonical for digest, non-canonical for wire" split is the standard UIDAI
enveloped-signature trick and must not be "fixed".

---

## 4. Auth v1.6 — ECB variant

`authSignXmlV16()`. Identical structure, but `<Data>`/`<Hmac>` use
AES-256-**ECB** with PKCS#7 padding instead of GCM — no IV, no AAD, no `ts`
prepend:

```
Data = <Data type="X">base64( aes256EcbEncrypt(sessionKey, pidXml) )</Data>
Hmac = <Hmac>base64( aes256EcbEncrypt(sessionKey, sha256(pidXml)) )</Hmac>
```

`<Skey>` (RSA wrap) and the signature are unchanged.

---

## 5. OTP v1.6 / v2.5 — sign only

`otpSignXmlV16` / `otpSignXmlV25` in `src/protocol/otp.cpp`. No session key, no
data encryption — an OTP request is just an XML-DSig-signed `<Otp>`:

```
c14n       = canonical <Otp> (closed-form <Opts></Opts> + blank line + </Otp>)
digest     = sha1(c14n) -> base64
signedInfo = c14nSignedInfo(digestB64)
sig        = rsaSha1Sign(AUA_private, signedInfo) -> base64
```

The only v1.6 vs v2.5 difference is the presence of the `tid` attribute.

---

## 6. eKYC v2.0 / v2.1 / v2.5 — wrapped auth

`ekycSignXmlV20` in `src/protocol/ekyc.cpp`:

1. Build a fully signed Auth XML with `authSignXmlV20` (Steps A–E above).
2. `base64Encode` that whole Auth document (single line, no line breaks).
3. Wrap it in `<Kyc …><Rad>…base64…</Rad></Kyc>`.

No extra encryption at the eKYC layer — the inner Auth XML is already
encrypted and signed. Version differences are only in the `<Kyc>` attribute set
(`ts`/`mec` appear in some versions, not others).

---

## 7. What happens on the server (decryption)

The inverse of the above, performed by UIDAI, not this client:

1. `rsaPrivateDecrypt(UIDAI_private, Skey)` → recover the 32-byte session key.
2. Re-derive IV/AAD from the `<Data>` timestamp prefix.
3. `aes256GcmDecrypt` (v2.0/2.5) or `aes256EcbDecrypt` (v1.6) → recover the
   Pid XML. The GCM tag / PKCS#7 padding is verified here — a wrong key or
   tampered payload fails.
4. `rsaSha1Verify(AUA_public, SignedInfo, SignatureValue)` → authenticate the
   request against the AUA certificate embedded in `<X509Certificate>`.

### Client-side decryption primitives

`aes256GcmDecrypt`, `aes256EcbDecrypt`, `rsaPrivateDecrypt`, and
`rsaSha1Verify` are implemented and unit-tested, but the request path only
*encrypts* and *signs*. Response handling (`parseResponseXml` in
`src/core/response_parser.cpp`) extracts `ret`/`err`/`code`/`actn`/`info`
status attributes and does not decrypt a KYC payload — matching the C
client's `parse_rsp`.

---

## 8. Byte-exactness checklist

The port must reproduce the C client's exact bytes. The easy-to-get-wrong
points, all handled in the code:

- base64 with **no line breaks** everywhere (`EVP_EncodeBlock`), except the
  certificate body which is re-wrapped at 64 columns (`certificateB64()`).
- GCM tag appended as 16 bytes after the ciphertext.
- IV = last 12 bytes of `ts`, AAD = last 16 bytes of `ts`.
- `<Data>` = `ts || ciphertext || tag`, then base64 (v2.0/2.5 only).
- Canonical `<Auth>`/`<Otp>` (closed-form tags) for the digest vs. the
  self-closing tags on the wire.
- RSA padding is PKCS#1 v1.5, not OAEP.
- ECB uses PKCS#7 padding (OpenSSL's `EVP_CIPHER_CTX_set_padding(ctx, 1)`).
