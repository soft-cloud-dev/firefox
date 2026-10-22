#!/bin/sh
set -eu

CA_URL=${SOFTCLOUD_CA_URL:-https://ipa.softcloud.dev/ipa/config/ca.crt}
CERTDATA=${SOFTCLOUD_CERTDATA:-security/nss/lib/ckfw/builtins/certdata.txt}
NICKNAME=${SOFTCLOUD_CA_NICKNAME:-SoftCloud.dev CA}

if [ ! -f "$CERTDATA" ]; then
  echo "certdata.txt not found: $CERTDATA" >&2
  exit 1
fi

ADDBUILTIN=${NSS_ADDBUILTIN:-}
if [ -z "$ADDBUILTIN" ]; then
  if command -v nss-addbuiltin >/dev/null 2>&1; then
    ADDBUILTIN=$(command -v nss-addbuiltin)
  elif command -v addbuiltin >/dev/null 2>&1; then
    ADDBUILTIN=$(command -v addbuiltin)
  else
    echo 'nss-addbuiltin/addbuiltin is required' >&2
    exit 1
  fi
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT HUP INT TERM
CRT=$TMP/softcloud-ca.crt
DER=$TMP/softcloud-ca.der
SNIPPET=$TMP/softcloud-certdata.txt

curl -k -fL "$CA_URL" -o "$CRT"

if ! openssl x509 -in "$CRT" -noout >/dev/null 2>&1; then
  echo 'downloaded file is not a valid X.509 certificate' >&2
  exit 1
fi

if ! openssl x509 -in "$CRT" -noout -ext basicConstraints 2>/dev/null | grep -Eq 'CA:TRUE([[:space:],]|$)'; then
  echo 'downloaded X.509 certificate does not have Basic Constraints CA:TRUE' >&2
  exit 1
fi

FINGERPRINT=$(openssl x509 -in "$CRT" -noout -fingerprint -sha256)
printf '%s\n' "$FINGERPRINT"
FINGERPRINT_HEX=${FINGERPRINT#*=}

if grep -Fq "$FINGERPRINT_HEX" "$CERTDATA"; then
  printf '%s\n' "SoftCloud.dev CA already present in $CERTDATA"
  exit 0
fi

if grep -Fq "# Certificate \"$NICKNAME\"" "$CERTDATA"; then
  echo "certificate nickname already exists with a different fingerprint: $NICKNAME" >&2
  exit 1
fi

openssl x509 -in "$CRT" -outform DER -out "$DER"
"$ADDBUILTIN" -t 'C,,' -n "$NICKNAME" -i "$DER" > "$SNIPPET"
sed -i '/^CKA_NSS_MOZILLA_CA_POLICY[[:space:]]/d' "$SNIPPET"

grep -Fq 'CKA_TRUST_SERVER_AUTH CK_TRUST CKT_NSS_TRUSTED_DELEGATOR' "$SNIPPET"
grep -Fq 'CKA_TRUST_EMAIL_PROTECTION CK_TRUST CKT_NSS_MUST_VERIFY_TRUST' "$SNIPPET"
grep -Fq 'CKA_TRUST_CODE_SIGNING CK_TRUST CKT_NSS_MUST_VERIFY_TRUST' "$SNIPPET"

cat "$SNIPPET" >> "$CERTDATA"
printf '%s\n' "Added $NICKNAME to Firefox/NSS trust data"
