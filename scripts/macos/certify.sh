#!/usr/bin/env bash
#
# scripts/macos/certify.sh — ограничение корневого сертификата Минцифры списком сайтов (macOS)
#
#   git clone <репозиторий> && cd <репозиторий>
#   ./scripts/macos/certify.sh rzd.ru job.alfabank.ru
#   ./scripts/macos/certify.sh --help
#
# Нужен Homebrew и OpenSSL 3 (brew install openssl@3). Общая логика — в scripts/common.sh.
# Firefox использует своё хранилище: импортируйте в него certs/ca.crt и certs/new_root_ca.crt вручную (см. README).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="scripts/macos/certify.sh"
USAGE_ENV=""
OPENSSL_HINT="Не найден OpenSSL 3 от Homebrew. Установите: brew install openssl@3
(системный LibreSSL не поддерживает нужную опцию -force_pubkey)."
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"

platform_check() { check_macos; }

platform_find_openssl() {
  local prefix c
  prefix="$(brew --prefix openssl@3 2>/dev/null || true)"
  for c in "${prefix:+$prefix/bin/openssl}" /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
    if [[ -n "$c" && -x "$c" ]]; then echo "$c"; return 0; fi
  done
  return 1
}

platform_prepare() { :; }

platform_confirm_text() {
  echo "Из системной связки ключей будут удалены сертификаты '$MY_CN', '$ROOT_CN' и 'Russian Trusted Sub CA'"
  echo "(включая оригинальный корень Минцифры, если он был установлен), затем установлены новые."
}

platform_install() {
  sudo -v
  remove_cert "$MY_CN"
  remove_cert "$ROOT_CN"
  remove_cert "Russian Trusted Sub CA"   # Sub CA в доверенных корнях стал бы точкой доверия в обход ограничений
  sudo security add-trusted-cert -d -r trustRoot -k "$KEYCHAIN" "$WORKDIR/ca.crt"
  sudo security add-trusted-cert -d -r trustRoot -k "$KEYCHAIN" "$WORKDIR/new_root_ca.crt"
}

platform_done() {
  say "Готово. Перезапустите браузер."
  say "Firefox использует своё хранилище: импортируйте в него вручную $(short "$WORKDIR")/ca.crt и new_root_ca.crt (см. README)."
  say "Если сертификаты Минцифры ставились и в связку «login», удалите их оттуда в Keychain Access."
}

mincifry_main "$@"