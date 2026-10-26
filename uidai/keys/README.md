# Keys & sandbox test data

Everything the C++ client needs for the UIDAI **staging** environment. Sources
are public, from <https://uidai.gov.in/en/data-and-download> (Sample Clients /
test data), except the AUA private key (see below).

## Files in this directory

| File | Role | Identity | Valid |
|------|------|----------|-------|
| `Staging_Signature_PrivateKey.p12` | AUA **private** key + cert (`password="public"`) → `rsaSha1Sign` | `CN=Public AUA for Staging Services` | May 24 2016 → **May 24 2020** (expired) |
| `uidai_auth_stage.cer` | UIDAI **public** key (old) → `rsaPublicEncrypt` session-key wrap | `CN=AuthStaging16092020` | …→ **Sep 16 2020** (expired) |
| `Auth_Private_Key_11082030.cer` | UIDAI **public** key (current) → session-key wrap | `CN=AuthStaging11082030` | Aug 11 2025 → **Aug 11 2030** ✅ |

> ⚠️ Naming: despite "Private_Key" in the filename, `Auth_Private_Key_11082030.cer`
> is a **public** certificate (self-signed UIDAI encryption key). It is *not*
> the AUA private key. SHA-256 fingerprint:
> `7B:CD:2B:F5:D5:F4:E8:D7:92:13:32:C0:F3:A4:D5:A8:D4:EF:CF:B6:71:C1:BC:77:E4:2E:50:B4:AB:04:44:97`

## The AUA private key is NOT downloadable

UIDAI publishes only *public* certificates. The AUA signing key (`.p12`) is
generated/provisioned to the AUA at onboarding and is never published. To do a
**live** sandbox run you must re-provision a current `.p12` from the AUA portal
(`developer.uidai.gov.in`); the bundled demo `.p12` is expired and only valid for
offline byte-exactness testing (what the golden tests do).

## License keys and codes

- `ac` / `sa` → `"public"`
- **AUA License Key** (`lk`): `MOw-DpjjHGxPlnKDXZlGh72zoPoryq4q5K1AhJL58HKfsoeCklXadcw`
- **ASA License Key**: `MGL5DLfGSNT6Eam2Gq_CtHARsi8HML0GpYH5tU_kg7XJ8YpkdtaL9TA`

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
