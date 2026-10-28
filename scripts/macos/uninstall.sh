#!/usr/bin/env bash
#
# scripts/macos/uninstall.sh — удаление сертификатов (и, по желанию, всего проекта), macOS
#
#   bash mincifry-ca-restrict/scripts/macos/uninstall.sh     # запускайте из папки выше проекта
#   bash .../uninstall.sh --certs -y                         # без вопросов: только сертификаты
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="scripts/macos/uninstall.sh"
# shellcheck source=../common.sh
source "$SCRIPT_DIR/../common.sh"

platform_check() { check_macos; }

platform_uninstall_certs() {
  sudo -v
  remove_cert "$MY_CN"
  remove_cert "$ROOT_CN"      # переподписанный корень Минцифры (и оригинальный, если он был установлен)
  say "Сертификаты удалены из системной связки ключей."
  say "Если вы импортировали их в Firefox вручную, удалите их и там."
}

uninstall_main "$@"