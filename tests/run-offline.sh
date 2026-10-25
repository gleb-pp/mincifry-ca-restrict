#!/usr/bin/env bash
# Offline test for macOS / Linux. Changes the SYSTEM trust store: runs only in CI.
# The scripts are run from a copy of the repository layout (scripts/, certs/) that contains the
# FAKE root, exactly like a user would run it after "git clone".
#   0. no terminal and no -y                          -> certify refuses to install
#   1. before: the fake Mincifry root is not trusted  -> connections fail
#   2. control: install the UNRESTRICTED root         -> good AND evil succeed (shows the problem)
#   3. default work dir (certs/)                      -> good OK, evil rejected; only 3 files are generated
#   4. --workdir + another list                       -> old list replaced; work dir holds only 3 files
#   5. --add -f FILE                                  -> lists are merged
#   6. --list                                         -> prints the saved list
#   7. uninstall: no terminal and no flags            -> refuses
#   8. uninstall --certs                              -> certificates are gone, project stays
#   9. uninstall --all from inside the project        -> refuses, nothing is deleted
#  10. uninstall --all from the parent directory      -> project folder (with the script itself) is deleted
set -uo pipefail
[[ "${CI:-}" == "true" ]] || { echo "This test modifies the system trust store and runs only in CI (CI=true)."; exit 2; }

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
UNAME="$(uname -s)"
WORK="$(mktemp -d)"
PKI="$WORK/pki"; MC="$WORK/mc"; REPO="$WORK/repo"
PIDS=()
trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT

as_root() { if [[ "$EUID" -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

CURL=curl
if [[ "$UNAME" == "Darwin" ]]; then
  OSDIR=macos
  CURL=/usr/bin/curl                                   # Apple curl uses the system keychain
  export OPENSSL="$(brew --prefix openssl@3)/bin/openssl"
else
  OSDIR=linux
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
pass() { echo "  PASS  $*"; }
fail() { echo "  FAIL  $*"; FAILS=$((FAILS+1)); }
tls() { "$CURL" -sS -o /dev/null --max-time 15 --resolve "$1:$2:127.0.0.1" "https://$1:$2/" 2>/dev/null; }
expect_ok() {
  tls "$2" "$3"; local rc=$?
  if [[ $rc -eq 0 ]]; then pass "$1: $2 accepted"; else fail "$1: $2 rejected (curl exit $rc), expected accepted"; fi
}
expect_rejected() {   # rejected because of the certificate, not because of a network problem
  tls "$2" "$3"; local rc=$?
  case $rc in
    0)       fail "$1: $2 accepted, expected rejected" ;;
    6|7|28)  fail "$1: $2 network problem (curl exit $rc)" ;;
    *)
      # the server must still be alive: otherwise "rejected" could be a false positive
      if "$CURL" -sk -o /dev/null --max-time 5 "https://127.0.0.1:$3/" 2>/dev/null; then pass "$1: $2 rejected (curl exit $rc)"
      else fail "$1: $2 test server is not responding"; fi ;;
  esac
}
expect_files() {   # dir, expected space-separated sorted names
  local got; got="$(ls -1 "$1" | sort | tr '\n' ' ' | sed 's/ $//')"
  if [[ "$got" == "$2" ]]; then pass "files in $(basename "$1"): $got"; else fail "files in $(basename "$1"): '$got', expected '$2'"; fi
}
run_script() { bash "$REPO/scripts/$OSDIR/certify.sh" -y "$@"; }
run_uninstall() { bash "$REPO/scripts/$OSDIR/uninstall.sh" "$@"; }
run_checked() {   # runs the script, checks the exit code and that the output is short
  local out rc
  out="$(run_script "$@" 2>&1)"; rc=$?
  if [[ $rc -ne 0 ]]; then fail "script exited with $rc: $out"; fi
  local n; n="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
  if [[ $n -le 12 ]]; then pass "concise output ($n lines)"; else fail "output is too long ($n lines): $out"; fi
}

echo "== setup: fake PKI, repository copy and local TLS servers"
bash "$ROOT_DIR/tests/fake-pki.sh" "$PKI" >/dev/null
mkdir -p "$REPO/certs" "$MC"
cp -R "$ROOT_DIR/scripts" "$REPO/scripts"
cp "$PKI/root.cer" "$REPO/certs/russian_trusted_root_ca.cer"
cp "$PKI/sub.cer"  "$REPO/certs/russian_trusted_sub_ca.cer"
printf '# sites list (test)\nmincifry-ci.test\n' > "$WORK/sites-list.txt"
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

echo "== 0. no terminal and no -y: must refuse to install"
bash "$REPO/scripts/$OSDIR/certify.sh" --workdir "$MC" mincifry-ci.test </dev/null >/dev/null 2>&1; rc=$?
if [[ $rc -ne 0 ]]; then pass "refused without a terminal (exit $rc)"; else fail "expected a refusal without a terminal"; fi

echo "== 1. before: nothing is trusted"
expect_rejected "before" good.mincifry-ci.test 9443

echo "== 2. control: unrestricted root is installed (this is the problem we solve)"
install_control_root || { echo "FAIL: cannot install the control root"; exit 1; }
expect_ok "control" good.mincifry-ci.test 9443
expect_ok "control" evil.not-listed.test 9445

echo "== 3. default work dir (certs/)"
run_checked mincifry-ci.test
expect_ok       "default" good.mincifry-ci.test 9443
expect_ok       "default" www.good.mincifry-ci.test 9444
expect_rejected "default" evil.not-listed.test 9445
expect_files "$REPO/certs" "ca.crt new_root_ca.crt russian_trusted_root_ca.cer russian_trusted_sub_ca.cer sites.txt"

echo "== 4. --workdir with another list: unrelated.test (old list must be replaced)"
run_checked --workdir "$MC" unrelated.test
expect_rejected "replaced" good.mincifry-ci.test 9443
expect_rejected "replaced" evil.not-listed.test 9445
expect_files "$MC" "ca.crt new_root_ca.crt sites.txt"

echo "== 5. --add -f FILE: lists are merged"
run_checked --workdir "$MC" --add -f "$WORK/sites-list.txt"
expect_ok       "merged" good.mincifry-ci.test 9443
expect_rejected "merged" evil.not-listed.test 9445

echo "== 6. --list"
n="$(bash "$REPO/scripts/$OSDIR/certify.sh" --workdir "$MC" --list | wc -l | tr -d ' ')"
if [[ "$n" == "2" ]]; then pass "--list prints 2 saved sites"; else fail "--list printed $n lines, expected 2"; fi

echo "== 7. uninstall without flags and without a terminal: must refuse"
run_uninstall </dev/null >/dev/null 2>&1; rc=$?
if [[ $rc -ne 0 ]]; then pass "refused without a terminal (exit $rc)"; else fail "expected a refusal without a terminal"; fi

echo "== 8. uninstall --certs"
out="$(run_uninstall --certs -y 2>&1)"; rc=$?
n="$(printf '%s\n' "$out" | wc -l | tr -d ' ')"
if [[ $rc -eq 0 && $n -le 6 ]]; then pass "certificates removed, concise output ($n lines)"; else fail "uninstall --certs: exit $rc, $n lines: $out"; fi
expect_rejected "uninstalled" good.mincifry-ci.test 9443
if [[ -d "$REPO/scripts" ]]; then pass "project folder is still there"; else fail "project folder was removed by --certs"; fi

echo "== 9. uninstall --all from inside the project: must refuse"
( cd "$REPO" && bash "scripts/$OSDIR/uninstall.sh" --all -y ) >/dev/null 2>&1; rc=$?
if [[ $rc -ne 0 && -d "$REPO/scripts" ]]; then pass "refused inside the project (exit $rc), nothing deleted"; else fail "expected a refusal inside the project (exit $rc)"; fi

echo "== 10. uninstall --all from the parent directory"
( cd "$WORK" && bash "repo/scripts/$OSDIR/uninstall.sh" --all -y ) >/dev/null 2>&1; rc=$?
if [[ $rc -eq 0 && ! -e "$REPO" ]]; then pass "project folder deleted together with the script"; else fail "project folder was not deleted (exit $rc)"; fi

echo
if [[ $FAILS -eq 0 ]]; then echo "ALL TESTS PASSED"; else echo "$FAILS CHECK(S) FAILED"; exit 1; fi
