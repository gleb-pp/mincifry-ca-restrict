#!/usr/bin/env bash
# Generates a fake "Mincifry" PKI for tests: Root -> Sub CA -> leaf certificates.
# usage: fake-pki.sh OUTDIR     (uses $OPENSSL or "openssl")
set -euo pipefail
export MSYS2_ARG_CONV_EXCL='*'   # Git Bash on Windows must not rewrite arguments like /C=RU/...
OSSL_BIN="${OPENSSL:-openssl}"
# openssl prints key-generation progress to stderr: show it only when a command fails
OSSL() { local out; out="$("$OSSL_BIN" "$@" 2>&1)" || { echo "$out" >&2; return 1; }; }
OUT="${1:?usage: fake-pki.sh OUTDIR}"
mkdir -p "$OUT"; cd "$OUT"
O="/C=RU/O=The Ministry of Digital Development and Communications"

OSSL req -x509 -newkey rsa:2048 -nodes -keyout root.key -out root.pem -days 3000 \
  -subj "$O/CN=Russian Trusted Root CA" \
  -addext "basicConstraints=critical,CA:true" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"

OSSL req -newkey rsa:2048 -nodes -keyout sub.key -out sub.csr -subj "$O/CN=Russian Trusted Sub CA"
printf 'basicConstraints=critical,CA:true\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > sub.ext
OSSL x509 -req -in sub.csr -CA root.pem -CAkey root.key -CAcreateserial -days 2000 -sha256 -extfile sub.ext -out sub.pem >/dev/null

mkleaf() {  # name hostname
  OSSL req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$2"
  printf 'subjectAltName=DNS:%s\nbasicConstraints=CA:false\nextendedKeyUsage=serverAuth\nauthorityKeyIdentifier=keyid\n' "$2" > "$1.ext"
  OSSL x509 -req -in "$1.csr" -CA sub.pem -CAkey sub.key -CAcreateserial -days 300 -sha256 -extfile "$1.ext" -out "$1.pem" >/dev/null
}
mkleaf good good.mincifry-ci.test            # inside the allowed list
mkleaf sub2 www.good.mincifry-ci.test        # sub-domain of an allowed domain
mkleaf evil evil.not-listed.test             # outside the list: must be rejected

# DER copies, as downloaded from gosuslugi.ru
OSSL x509 -in root.pem -outform DER -out root.cer
OSSL x509 -in sub.pem  -outform DER -out sub.cer
echo "fake PKI ready in $OUT"