#!/usr/bin/env bash
#
# scripts/linux/uninstall.sh — удаление сертификатов (и, по желанию, всего проекта), Linux
#
#   bash mincifry-ca-restrict/scripts/linux/uninstall.sh     # запускайте из папки выше проекта
#   bash .../uninstall.sh --certs -y                         # без вопросов: только сертификаты
set -euo pipefail
export PATH="$PATH:/usr/sbin:/sbin"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="scripts/linux/uninstall.sh"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"

platform_check() { check_linux; }

platform_uninstall_certs() {
  detect_trust_backend || die "Ваш дистрибутив не поддерживается (скрипт умеет Debian/Ubuntu, Fedora и Arch)."
  if [[ "$EUID" -ne 0 ]]; then
    command -v sudo >/dev/null 2>&1 || die "Нужны права root: установите sudo или запустите скрипт от root."
    sudo -v
  fi
  as_root rm -f "$ANCHOR_DIR/$OUR_CA_NAME" "$ANCHOR_DIR/$OUR_RU_NAME"
  as_root "${UPDATE_CMD[@]}" >"$LOG" 2>&1 || { cat "$LOG" >&2; die "Не удалось обновить хранилище (${UPDATE_CMD[*]})."; }
  say "Сертификаты удалены из системного хранилища ($BACKEND)."
  say "Если вы импортировали их в Firefox или Chrome вручную, удалите их и там."
}

uninstall_main "$@"