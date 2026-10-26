#!/bin/bash
#
# End-to-end UIDAI sandbox smoke test for the C++ client.
#
# Sends a signed Auth v2.0 request through uidai_cli (fork/wish + libevent +
# UidaiClient) and captures the raw HTTP request/response to cpp/dumps/ for
# offline reference. The request uses UIDAI's public staging test data:
# seeded UID, current AUA license key, and the current staging public cert.
#
# Note: a *successful* round-trip needs (a) network access to
# developer.uidai.gov.in and (b) a valid (unexpired) AUA private key. On an
# offline host this ends in "transport: timeout", but the signed request is
# still dumped and byte-inspectable.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
KEYS="$REPO_ROOT/uidai/keys"
GUI="$REPO_ROOT/uidai/gui"
CLI="$REPO_ROOT/cpp/build/uidai_cli"
DUMP_DIR="$REPO_ROOT/cpp/dumps"

[ -x "$CLI" ] || { echo "uidai_cli not built; run cmake --build cpp/build" >&2; exit 1; }
[ -f "$KEYS/Staging_Signature_PrivateKey.p12" ] || { echo "missing AUA .p12" >&2; exit 1; }
[ -f "$KEYS/Auth_Private_Key_11082030.cer" ] || { echo "missing UIDAI public cert" >&2; exit 1; }

# Seeded test UID 999941057058 (Shivshankar Choudhury) + current AUA/ASA keys.
# `lk` (AUA key) signs the XML; `asalk` (ASA key) is the URL's final segment.
REQUEST='/request?stage=staging&request=auth&auth={uid=999941057058,tid=public,txn=TXN:Shivshankar,ac=public,sa=public,ver=2.5,lk=MOw-DpjjHGxPlnKDXZlGh72zoPoryq4q5K1AhJL58HKfsoeCklXadcw,asalk=MGL5DLfGSNT6Eam2Gq_CtHARsi8HML0GpYH5tU_kg7XJ8YpkdtaL9TA,rc=Y}&uses={pi=1,pa=0,pfa=0,bio=0,pv=0,demo=1}&tkn={type=NA}&meta={dc=Balaagh}&pi={ms=E,mv=100,name=Shivshankar+Choudhury,gender=M,dob=13-05-1968,dobt=V,phone=2810806979,email=sschoudhury@dummyemail.com}&demo={lang=NA}&uidai={uri=/authserver/2.5,host=developer.uidai.gov.in,scheme=https,port=443}&crypto={public=Auth_Private_Key_11082030.cer,private=Staging_Signature_PrivateKey.p12,password=public}'

# Fake `wish`: read the boot command, emit one request line, read the response,
# then do the Exit handshake. Mirrors the real GUI pipe protocol.
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/wish" <<EOF
#!/bin/sh
read boot
printf '%s\n' "$REQUEST"
read resp
printf 'RESPONSE:[%s]\n' "\$resp" >&2
printf '%s\n' 'Exit'
read exitline
exit 0
EOF
chmod +x "$TMP/wish"

mkdir -p "$DUMP_DIR"
cd "$KEYS"
PATH="$TMP:$PATH" UIDAI_DUMP_DIR="$DUMP_DIR" "$CLI" "$GUI"

echo
echo "Captured HTTP traffic in $DUMP_DIR:"
ls -la "$DUMP_DIR"
echo
echo "--- signed request (request_0.http) ---"
sed -n '1,12p' "$DUMP_DIR"/request_0.http
