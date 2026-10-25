#!/usr/bin/env bash
#
# certify-linux.sh — ограничение корневого сертификата Минцифры списком сайтов (Linux)
#
#   git clone <репозиторий> && cd <репозиторий>
#   ./scripts/certify-linux.sh --popular                # готовый список популярных сайтов
#   ./scripts/certify-linux.sh rzd.ru tbank.ru          # свой список
#   ./scripts/certify-linux.sh --add alfabank.ru        # дописать к сохранённому списку
#   ./scripts/certify-linux.sh --help
#
# Поддерживаются Debian/Ubuntu, Fedora и Arch. Общая логика — в scripts/lib/common.sh.
# Firefox и Chrome/Chromium на Linux не читают системное хранилище: импортируйте в них
# certs/ca.crt и certs/new_root_ca.crt вручную (см. README).
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"      # update-ca-* лежат в sbin, которого может не быть в PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="certify-linux.sh"
USAGE_EXTRA=", OPENSSL (путь к openssl: нужен OpenSSL 1.1.1+ с опцией -force_pubkey)"
OPENSSL_HINT="Не найден OpenSSL с поддержкой -force_pubkey (нужна версия 1.1.1 или новее).
Обновите пакет openssl или укажите путь: OPENSSL=/путь/к/openssl $SCRIPT_NAME ..."
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

# имена файлов в системном хранилище (на Debian/Ubuntu обязательно расширение .crt)
OUR_CA_NAME="mincifry-restricted-root.crt"
OUR_RU_NAME="mincifry-restricted-russian-root.crt"
ANCHOR_DIR=""; UPDATE_CMD=(); BACKEND=""; FOREIGN=""

as_root() { if [[ "$EUID" -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

platform_check() {
  [[ "$(uname -s)" == "Linux" ]] || die "Этот скрипт рассчитан на Linux. Для macOS используйте scripts/certify-macos.sh."
  if [[ "$EUID" -eq 0 ]]; then
    [[ -z "${SUDO_USER:-}" ]] || die "Не запускайте через sudo: sudo будет вызван только там, где нужно."
    warn "скрипт запущен от root."
  fi
}

platform_find_openssl() {
  local c help
  for c in "${OPENSSL:-}" openssl; do
    [[ -n "$c" ]] || continue
    command -v "$c" >/dev/null 2>&1 || continue
    help="$("$c" x509 -help 2>&1 || true)"
    if grep -q 'force_pubkey' <<<"$help"; then command -v "$c"; return 0; fi
  done
  return 1
}

platform_search_dirs() {
  add_search_dir "$(xdg-user-dir DOWNLOAD 2>/dev/null || true)"
  add_search_dir "$HOME/Загрузки"
}

detect_trust_backend() {
  local upd
  if upd="$(command -v update-ca-certificates 2>/dev/null)" && [[ -f /etc/debian_version ]]; then
    ANCHOR_DIR=/usr/local/share/ca-certificates; UPDATE_CMD=("$upd" --fresh); BACKEND="Debian/Ubuntu"
  elif upd="$(command -v update-ca-trust 2>/dev/null)"; then
    if [[ -d /etc/pki/ca-trust/source/anchors ]]; then              # Fedora
      ANCHOR_DIR=/etc/pki/ca-trust/source/anchors; UPDATE_CMD=("$upd"); BACKEND="Fedora"
    elif [[ -d /etc/ca-certificates/trust-source/anchors ]]; then   # Arch
      ANCHOR_DIR=/etc/ca-certificates/trust-source/anchors; UPDATE_CMD=("$upd"); BACKEND="Arch"
    else
      return 1
    fi
  else
    return 1
  fi
}

# Где мог остаться оригинальный корень (или Sub CA) Минцифры, в том числе по статье-первоисточнику.
# Sub CA среди доверенных якорей тоже обходит ограничения, поэтому ищем и его.
find_foreign_roots() {
  local dir f tmp="$TMPD/foreign.pem" seen=" "
  local dirs=("$ANCHOR_DIR" /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors \
    /usr/share/pki/ca-trust-source/anchors /etc/ca-certificates/trust-source/anchors)
  for dir in "${dirs[@]}"; do
    [[ -d "$dir" ]] || continue
    if [[ "$seen" == *" $dir "* ]]; then continue; fi
    seen+="$dir "
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      case "$(basename "$f")" in "$OUR_CA_NAME"|"$OUR_RU_NAME") continue ;; esac
      if to_pem "$f" "$tmp" && "$OSSL" x509 -in "$tmp" -noout -subject 2>/dev/null | grep -qE "$ROOT_CN|Russian Trusted Sub CA"; then
        echo "$f"
      fi
    done < <(find "$dir" -maxdepth 1 \( -type f -o -type l \) 2>/dev/null)
  done
}

platform_prepare() {
  detect_trust_backend || die "Ваш дистрибутив не поддерживается (скрипт умеет Debian/Ubuntu, Fedora и Arch).
Сертификаты собраны в $WORKDIR (ca.crt и new_root_ca.crt): установите их вручную по инструкции дистрибутива."
  FOREIGN="$(find_foreign_roots)"
}

platform_confirm_text() {
  echo "Будет обновлено системное хранилище ($BACKEND): прежние версии удалены, новые установлены."
  if [[ -n "$FOREIGN" ]]; then
    echo "Заодно будут удалены другие сертификаты Минцифры (иначе они обходят ограничения):"
    printf '  %s\n' $FOREIGN
  fi
}

platform_install() {
  if [[ "$EUID" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "Нужны права root: установите sudo или запустите скрипт от root."
    sudo -v
  fi
  as_root rm -f "$ANCHOR_DIR/$OUR_CA_NAME" "$ANCHOR_DIR/$OUR_RU_NAME"
  local f
  for f in $FOREIGN; do as_root rm -f "$f"; done
  as_root mkdir -p "$ANCHOR_DIR"
  as_root install -m 0644 "$WORKDIR/ca.crt" "$ANCHOR_DIR/$OUR_CA_NAME"
  as_root install -m 0644 "$WORKDIR/new_root_ca.crt" "$ANCHOR_DIR/$OUR_RU_NAME"
  as_root "${UPDATE_CMD[@]}" >"$LOG" 2>&1 || { cat "$LOG" >&2; die "Не удалось обновить хранилище (${UPDATE_CMD[*]})."; }
}

platform_done() {
  say "Готово. Перезапустите браузер."
  say "Firefox и Chrome/Chromium на Linux используют свои базы: импортируйте в них вручную $(short "$WORKDIR")/ca.crt и new_root_ca.crt (см. README)."
}

mincifry_main "$@"
