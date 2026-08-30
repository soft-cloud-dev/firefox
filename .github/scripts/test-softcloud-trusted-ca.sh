#!/bin/sh
set -eu

SCRIPT=${SCRIPT:-"$(dirname "$0")/prepare-softcloud-trusted-ca.sh"}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM

make_cert() {
  name=$1
  is_ca=$2
  crt=$3
  key=$4
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
    -subj "/CN=$name" \
    -addext "basicConstraints=critical,CA:$is_ca" \
    -keyout "$key" -out "$crt" >/dev/null 2>&1
}

make_cert 'SoftCloud Test CA' TRUE "$TMP/ca.crt" "$TMP/ca.key"
make_cert 'Not A CA' FALSE "$TMP/not-ca.crt" "$TMP/not-ca.key"
printf 'BEGINDATA\n' > "$TMP/certdata.txt"

SOFTCLOUD_CA_URL="file://$TMP/ca.crt" \
SOFTCLOUD_CERTDATA="$TMP/certdata.txt" \
SOFTCLOUD_CA_NICKNAME='SoftCloud.dev CA' \
  "$SCRIPT" >"$TMP/out.log" 2>"$TMP/err.log"

grep -q '^sha256 Fingerprint=' "$TMP/out.log"
grep -Fq '# Certificate "SoftCloud.dev CA"' "$TMP/certdata.txt"
grep -Fq 'CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR' "$TMP/certdata.txt"
grep -Fq 'CKA_TRUST_EMAIL_PROTECTION CK_TRUST CKT_NSS_MUST_VERIFY_TRUST' "$TMP/certdata.txt"
grep -Fq 'CKA_TRUST_CODE_SIGNING CK_TRUST CKT_NSS_MUST_VERIFY_TRUST' "$TMP/certdata.txt"
if grep -Fq 'CKA_NSS_MOZILLA_CA_POLICY' "$TMP/certdata.txt"; then
  echo 'private CA must not be marked as Mozilla public CA' >&2
  exit 1
fi

before=$(sha256sum "$TMP/certdata.txt" | awk '{print $1}')
SOFTCLOUD_CA_URL="file://$TMP/ca.crt" \
SOFTCLOUD_CERTDATA="$TMP/certdata.txt" \
SOFTCLOUD_CA_NICKNAME='SoftCloud.dev CA' \
  "$SCRIPT" >"$TMP/out2.log" 2>"$TMP/err2.log"
after=$(sha256sum "$TMP/certdata.txt" | awk '{print $1}')
[ "$before" = "$after" ]
grep -Fq 'already present' "$TMP/out2.log"

cp "$TMP/certdata.txt" "$TMP/certdata.before-bad"
if SOFTCLOUD_CA_URL="file://$TMP/not-ca.crt" \
   SOFTCLOUD_CERTDATA="$TMP/certdata.txt" \
   SOFTCLOUD_CA_NICKNAME='Rejected CA' \
   "$SCRIPT" >"$TMP/bad.out" 2>"$TMP/bad.err"; then
  echo 'CA:FALSE certificate was accepted' >&2
  exit 1
fi
cmp "$TMP/certdata.before-bad" "$TMP/certdata.txt"
grep -Fq 'CA:TRUE' "$TMP/bad.err"
