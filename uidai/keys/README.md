# Keys & sandbox test data

Everything the C++ client needs for the UIDAI **staging** environment. Sources
are public, from <https://uidai.gov.in/en/data-and-download> (Sample Clients /
test data), except the AUA private key (see below).

## Files in this directory

| File | Role | Identity | Valid |
|------|------|----------|-------|
| `Staging_Signature_PrivateKey.p12` | AUA **private** key + cert (`password="public"`) → `rsaSha1Sign` (bundled demo, from the 2018 sample) | `CN=Public AUA for Staging Services` | May 24 2016 → **May 24 2020** (expired) |
| `PublicAUAforStagingServices.p12` | AUA **private** key + cert (the *newest* public sample-client keystore, from `github.com/uidaitc/authapiclient`) | `CN=Public AUA for Staging Services` | May 25 2020 → **May 25 2024** (expired) |
| `uidai_auth_stage.cer` | UIDAI **public** key (old) → `rsaPublicEncrypt` session-key wrap | `CN=AuthStaging16092020` | …→ **Sep 16 2020** (expired) |
| `Auth_Private_Key_11082030.cer` | UIDAI **public** key (current) → session-key wrap | `CN=AuthStaging11082030` | Aug 11 2025 → **Aug 11 2030** ✅ |

> ⚠️ Naming: despite "Private_Key" in the filename, `Auth_Private_Key_11082030.cer`
> is a **public** certificate (self-signed UIDAI encryption key). It is *not*
> the AUA private key. SHA-256 fingerprint:
> `7B:CD:2B:F5:D5:F4:E8:D7:92:13:32:C0:F3:A4:D5:A8:D4:EF:CF:B6:71:C1:BC:77:E4:2E:50:B4:AB:04:44:97`

## The AUA private key is NOT downloadable

UIDAI publishes only *public* certificates. The AUA signing key (`.p12`) is
provisioned to the AUA and never published as a download. The authoritative
[Testing Data and License Keys](https://uidai.gov.in/en/data-and-download#testing-data-and-license-keys)
page says so explicitly:

> Keystore for digital signature for "public" AUA — you can request the `.p12`
> by writing to **authsupport@uidai.net.in**.

Even the newest public sample-client keystore shipped with
[`uidaitc/authapiclient`](https://github.com/uidaitc/authapiclient)
(`PublicAUAforStagingServices.p12`, included here) lapsed **25 May 2024**, so no
downloadable AUA key is currently valid. To get a `ret="y"` from the live
sandbox, request a current `.p12` from `authsupport@uidai.net.in` and drop it in
this directory; the bundled demo keys are expired and only valid for offline
byte-exactness testing (what the golden tests do).

## License keys and codes

- `ac` / `sa` → `"public"`
- **AUA License Key** (`<Auth lk="…">`, the XML attribute): `MOw-DpjjHGxPlnKDXZlGh72zoPoryq4q5K1AhJL58HKfsoeCklXadcw`
- **ASA License Key** (`<asalk>` — the *last URL path segment*): `MGL5DLfGSNT6Eam2Gq_CtHARsi8HML0GpYH5tU_kg7XJ8YpkdtaL9TA`

> These are now **two different values**. In the 2018-era sample clients both
> positions carried the same "public" key, which is why the C client reuses one
> string for both. Against the live sandbox they must be split (see *Endpoint*).

## Endpoint (verified against the live sandbox)

The modern staging API is HTTPS-only (`:443`; plain-HTTP `:80` is closed) and
version-qualified in the path:

```
POST https://developer.uidai.gov.in/authserver/2.5/public/<uid[0]>/<uid[1]>/<asalk>
POST https://developer.uidai.gov.in/uidotp/2.5/public/<uid[0]>/<uid[1]>/<asalk>
POST https://developer.uidai.gov.in/uidkyc/kyc/2.5/public/<uid[0]>/<uid[1]>/<asalk>
```

- `authserver` / `uidotp` / `uidkyc/kyc` → service prefix (not `/uidauth`).
- `<ver>` in the URL must match the request's `ver` attribute (2.5 is the live
  default; 2.0/1.6 paths now 404).
- `<asalk>` is the **ASA** license key (`MGL5DLfG…`), *not* the AUA `lk`.

The C++ client reaches this endpoint natively: `uidai={…,scheme=https,port=443}`
selects the HTTPS transport, and `auth={…,asalk=…}` supplies the ASA key for the
URL segment (falling back to `lk` when `asalk` is absent, for the 2018-era
one-key samples). `cpp/tools/sandbox_test.sh` drives `uidai_cli` over this path
end-to-end.

## Verified live-sandbox result

POSTing the signed v2.5 body over HTTPS returns a signed `<AuthRes>` from UIDAI:

| Stage | Result |
|-------|--------|
| old path `/uidauth/public/9/9/…` | `404` (endpoint moved) |
| `ver=2.0` body → `…/authserver/2.5/…` | `err=540` — "invalid Auth XML version" |
| AUA key in URL `<asalk>` | `err=940` — "unauthorized ASA channel" |
| ASA key in URL, valid path + version | `err=570` — "invalid key info in digital signature" (AUA cert expired/not-authorized) |

`err=570` is reached only after UIDAI has decrypted and processed the payload —
so the C++ crypto/signing is byte-correct end-to-end. The remaining blocker to a
`ret="y"` is the **expired AUA `.p12`** (bundled one lapsed May 2020), which is
not downloadable and must be re-provisioned from the AUA portal.

## Seeded test Aadhaar numbers (with demographic data)

| UID | Name | Gender | DOB | dobt | Phone | Email | State / PIN |
|-----|------|--------|-----|------|-------|-------|-------------|
| 999941057058 | Shivshankar Choudhury | M | 13-05-1968 | V | 2810806979 | sschoudhury@dummyemail.com | New Delhi 110002 |
| 999971658847 | Kumar Agarwal | M | 04-05-1978 | A | 2314475929 | kma@mailserver.com | Rajasthan 313001 |
| 999933119405 | Fatima Bedi | F | 30-07-1943 | A | 2837032088 | bedi2020@mailserver.com | Uttar Pradesh 243001 |
| 999955183433 | Rohit Pandey | M | 08-07-1985 | A | 2821096353 | rpandey@mailserver.com | Maharashtra 243001 |
| 999990501894 | Anisha Jay Kapoor | F | 01-01-1982 | V | — | — | Karnataka 560036 |

## Certificate download URLs

Staging (public keys, from the data-and-download page):

- Current: `https://backend.uidai.gov.in/get/files/media/document/2026-07/Auth_Private_Key_11082030.cer`
- `https://backend.uidai.gov.in/get/files/media/document/2026-07/AuthStaging25082025.cer` (expired Aug 2025)
- `https://backend.uidai.gov.in/get/files/media/document/2026-07/uidai_auth_stage.cer` (expired Sep 2020)

Pre-production / production public keys and digital-signature certs are listed on
the same page under the Sample Clients section.

## How the client uses these

`KeyStore::load(p12Path, password, cerPath)` loads the AUA private key (`.p12`)
and the UIDAI public key (`.cer`). The request line's `crypto={public=<cer>,private=<p12>,password=<pw>}`
names them; `lk=` carries the AUA license key. For a live sandbox call, point
`public` at `Auth_Private_Key_11082030.cer` and use the current AUA license key
and a valid AUA `.p12`.
