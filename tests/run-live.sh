#!/usr/bin/env bash
# LIVE smoke test against the real site (Linux / Debian-family runner). Not blocking: network dependent.
#   0. preflight: the site is reachable from the runner (GitHub IPs may be geo-blocked -> test is skipped)
#   1. baseline: a clean runner does not trust Mincifry         -> TLS to the site fails
#   2. control:  the UNRESTRICTED real root is installed        -> the site (and the negative-control site) work
#   3. our script with the site                                 -> the site works, the other Mincifry site is rejected
# Uses the real root certificate committed to certs/russian_trusted_root_ca.cer (DER or PEM).
set -uo pipefail
[[ "${CI:-}" == "true" ]] || { echo "This test modifies the system trust store and runs only in CI (CI=true)."; exit 2; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="${MINCIFRY_SCRIPT:-$ROOT_DIR/scripts/linux/certify.sh}"
FIXTURE="${MINCIFRY_ROOT_FIXTURE:-$ROOT_DIR/certs/russian_trusted_root_ca.cer}"      # the real root committed to the repo
SITE="${LIVE_SITE:-rzd.ru}"
NEG="${LIVE_NEG_SITE:-online.sberbank.ru}"      # a Mincifry-signed site that is NOT in our list
SUMMARY="${GITHUB_STEP_SUMMARY:-/dev/null}"
WORK="$(mktemp -d)"

as_root() { if [[ "$EUID" -eq 0 ]]; then "$@"; else sudo "$@"; fi; }
skip() { echo "::warning::live test skipped: $1"; echo "**Live test skipped:** $1" >> "$SUMMARY"; exit 0; }
curl_ok() { curl -sS -o /dev/null --max-time 30 "https://$1" 2>/dev/null; }

[[ -f "$FIXTURE" ]] || skip "certs/russian_trusted_root_ca.cer is missing from the repository"

FMT=DER; openssl x509 -inform DER -in "$FIXTURE" -noout >/dev/null 2>&1 || FMT=PEM
openssl x509 -inform "$FMT" -in "$FIXTURE" -noout -subject | grep -q "Russian Trusted Root CA" \
  || { echo "FAIL: the fixture is not 'Russian Trusted Root CA'"; exit 1; }
FP="$(openssl x509 -inform "$FMT" -in "$FIXTURE" -noout -fingerprint -sha256 | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')"
echo "fixture SHA-256: $FP"
if [[ -n "${MINCIFRY_ROOT_SHA256:-}" ]]; then
  WANT="$(printf '%s' "$MINCIFRY_ROOT_SHA256" | tr -d ': ' | tr 'A-F' 'a-f')"
  [[ "$FP" == "$WANT" ]] || { echo "FAIL: fixture fingerprint does not match MINCIFRY_ROOT_SHA256"; exit 1; }
fi
openssl x509 -inform "$FMT" -in "$FIXTURE" -out "$WORK/root.pem"

echo "== 0. preflight"
curl -sk -o /dev/null --max-time 25 "https://$SITE" || skip "$SITE is not reachable from the runner (geo-blocking or network problem)"

echo "== 1. baseline"
curl_ok "$SITE" && skip "the runner already trusts $SITE without our certificates"
echo "  PASS  $SITE is rejected on a clean runner"

echo "== 2. control: unrestricted original root"
as_root install -m 0644 "$WORK/root.pem" /usr/local/share/ca-certificates/live-control-root.crt && as_root update-ca-certificates >/dev/null
curl_ok "$SITE" || skip "$SITE is not accepted even with the unrestricted root (the site may have changed its CA)"
echo "  PASS  $SITE accepted with the unrestricted root"
NEG_PREMISE=0
if curl_ok "$NEG"; then NEG_PREMISE=1; echo "  PASS  $NEG accepted with the unrestricted root (negative control is valid)"
else echo "  NOTE  $NEG is not accepted with the unrestricted root: negative check will be skipped"; fi

echo "== 3. our script"
FAILS=0
if ! bash "$SCRIPT" -y "$SITE"; then echo "  FAIL  script exited with an error"; FAILS=$((FAILS+1)); fi
if curl_ok "$SITE"; then echo "  PASS  $SITE accepted after the script"; else echo "  FAIL  $SITE rejected after the script"; FAILS=$((FAILS+1)); fi
if [[ $NEG_PREMISE -eq 1 ]]; then
  curl_ok "$NEG"; rc=$?
  case $rc in
    0)      echo "  FAIL  $NEG accepted, expected rejected"; FAILS=$((FAILS+1)) ;;
    6|7|28) echo "  FAIL  $NEG network problem (curl exit $rc)"; FAILS=$((FAILS+1)) ;;
    *)      echo "  PASS  $NEG rejected (curl exit $rc)" ;;
  esac
fi

{
  echo "### Live test: $SITE"
  echo "- fixture SHA-256: \`$FP\`"
  echo "- negative control site: \`$NEG\` (premise valid: $NEG_PREMISE)"
  [[ $FAILS -eq 0 ]] && echo "- **result: passed**" || echo "- **result: $FAILS check(s) failed**"
} >> "$SUMMARY"
[[ $FAILS -eq 0 ]] && echo "ALL LIVE CHECKS PASSED" || { echo "$FAILS LIVE CHECK(S) FAILED"; exit 1; }
