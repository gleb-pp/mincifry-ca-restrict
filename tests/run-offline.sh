#!/usr/bin/env bash
# Offline test for macOS / Linux. Changes the SYSTEM trust store: runs only in CI.
#   1. before: the fake Mincifry root is not trusted        -> connections fail
#   2. control: install the UNRESTRICTED root               -> good AND evil succeed (shows the problem)
#   3. our script with a site list                          -> good succeeds, evil is rejected
#   4. our script with another list                         -> good is rejected (list was replaced)
set -uo pipefail
[[ "${CI:-}" == "true" ]] || { echo "This test modifies the system trust store and runs only in CI (CI=true)."; exit 2; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
UNAME="$(uname -s)"
WORK="$(mktemp -d)"
PKI="$WORK/pki"; DL="$WORK/dl"; MC="$WORK/mc"
mkdir -p "$DL" "$MC"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT

as_root() { if [[ "$EUID" -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

CURL=curl
if [[ "$UNAME" == "Darwin" ]]; then
  SCRIPT="${MINCIFRY_SCRIPT:-$ROOT_DIR/scripts/certify-macos.sh}"
  CURL=/usr/bin/curl                                   # Apple curl uses the system keychain
  export OPENSSL="$(brew --prefix openssl@3)/bin/openssl"
else
  SCRIPT="${MINCIFRY_SCRIPT:-$ROOT_DIR/scripts/certify-linux.sh}"
fi
OPENSSL="${OPENSSL:-openssl}"; export OPENSSL

install_control_root() {   # the original-style root WITHOUT restrictions
  if [[ "$UNAME" == "Darwin" ]]; then
    as_root security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$PKI/root.pem"
  elif [[ -f /etc/debian_version ]]; then
    as_root install -m 0644 "$PKI/root.pem" /usr/local/share/ca-certificates/ci-control-root.crt && as_root update-ca-certificates
  elif [[ -d /etc/pki/ca-trust/source/anchors ]]; then
    as_root install -m 0644 "$PKI/root.pem" /etc/pki/ca-trust/source/anchors/ci-control-root.crt && as_root update-ca-trust
  else
    as_root install -m 0644 "$PKI/root.pem" /etc/ca-certificates/trust-source/anchors/ci-control-root.crt && as_root update-ca-trust
  fi
}

FAILS=0
tls() { "$CURL" -sS -o /dev/null --max-time 15 --resolve "$1:$2:127.0.0.1" "https://$1:$2/" 2>/dev/null; }
expect_ok() {
  tls "$2" "$3"; local rc=$?
  if [[ $rc -eq 0 ]]; then echo "  PASS  $1: $2 accepted"; else echo "  FAIL  $1: $2 rejected (curl exit $rc), expected accepted"; FAILS=$((FAILS+1)); fi
}
expect_rejected() {   # rejected because of the certificate, not because of a network problem
  tls "$2" "$3"; local rc=$?
  case $rc in
    0)       echo "  FAIL  $1: $2 accepted, expected rejected"; FAILS=$((FAILS+1)) ;;
    6|7|28)  echo "  FAIL  $1: $2 network problem (curl exit $rc)"; FAILS=$((FAILS+1)) ;;
    *)
      # the server must still be alive: otherwise "rejected" could be a false positive
      if "$CURL" -sk -o /dev/null --max-time 5 "https://127.0.0.1:$3/" 2>/dev/null; then
        echo "  PASS  $1: $2 rejected (curl exit $rc)"
      else
        echo "  FAIL  $1: $2 test server is not responding"; FAILS=$((FAILS+1))
      fi ;;
  esac
}
# The script is run from a copy of the repository layout (scripts/ + certs/) that contains the FAKE root,
# exactly like a user would run it after "git clone": no --root-ca, the root is picked up from certs/.
REPO="$WORK/repo"
run_script() { bash "$REPO/scripts/$(basename "$SCRIPT")" -y --workdir "$MC" "$@"; }

echo "== setup: fake PKI and local TLS servers"
bash "$ROOT_DIR/tests/fake-pki.sh" "$PKI" >/dev/null
mkdir -p "$REPO/scripts" "$REPO/certs"
cp "$SCRIPT" "$REPO/scripts/"
cp "$PKI/root.cer" "$REPO/certs/russian_trusted_root_ca.cer"
cp "$PKI/sub.cer"  "$REPO/certs/russian_trusted_sub_ca.cer"
for spec in good:9443 sub2:9444 evil:9445; do
  "$OPENSSL" s_server -accept "${spec#*:}" -cert "$PKI/${spec%%:*}.pem" -key "$PKI/${spec%%:*}.key" \
    -cert_chain "$PKI/sub.pem" -www -quiet >/dev/null 2>&1 &
  PIDS+=($!)
done
for i in $(seq 1 20); do
  "$CURL" -sk -o /dev/null --max-time 3 "https://127.0.0.1:9443/" 2>/dev/null && "$CURL" -sk -o /dev/null --max-time 3 "https://127.0.0.1:9445/" 2>/dev/null && break
  sleep 0.5
done
"$CURL" -sk -o /dev/null --max-time 5 "https://127.0.0.1:9443/" || { echo "FAIL: local TLS server did not start"; exit 1; }

echo "== 0. no terminal and no --workdir: the script must refuse and create nothing"
DEFAULT_DIR="$REPO/certs/generated"     # default work dir of the script (inside the repo copy)
bash "$REPO/scripts/$(basename "$SCRIPT")" rzd.test </dev/null >/dev/null 2>&1; rc=$?
if [[ $rc -ne 0 && ! -e "$DEFAULT_DIR" ]]; then
  echo "  PASS  refused to run without a terminal (exit $rc), default work dir not created"
else
  echo "  FAIL  expected a refusal without a terminal (exit $rc) and no default work dir"; FAILS=$((FAILS+1))
fi

echo "== 1. before: nothing is trusted"
expect_rejected "before" good.mincifry-ci.test 9443

echo "== 2. control: unrestricted root is installed (this is the problem we solve)"
install_control_root || { echo "FAIL: cannot install the control root"; exit 1; }
expect_ok "control" good.mincifry-ci.test 9443
expect_ok "control" evil.not-listed.test 9445

echo "== 3. script with list: mincifry-ci.test"
run_script mincifry-ci.test || { echo "FAIL: script exited with an error"; FAILS=$((FAILS+1)); }
expect_ok       "restricted" good.mincifry-ci.test 9443
expect_ok       "restricted" www.good.mincifry-ci.test 9444
expect_rejected "restricted" evil.not-listed.test 9445

echo "== 4. script with another list: unrelated.test (old list must be replaced)"
run_script unrelated.test || { echo "FAIL: script exited with an error"; FAILS=$((FAILS+1)); }
expect_rejected "replaced" good.mincifry-ci.test 9443
expect_rejected "replaced" evil.not-listed.test 9445

echo
if [[ $FAILS -eq 0 ]]; then echo "ALL TESTS PASSED"; else echo "$FAILS CHECK(S) FAILED"; exit 1; fi
