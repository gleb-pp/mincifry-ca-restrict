#!/usr/bin/env bash
#
# certify-linux.sh.sh — ограничение корневого сертификата Минцифры списком сайтов (Linux)
#
# Что делает:
#   1. создаёт свой корневой сертификат с nameConstraints (только ваши домены);
#   2. переподписывает им корень Минцифры (тот же subject и публичный ключ);
#   3. проверяет цепочку на ваших сайтах;
#   4. удаляет старые версии из системного хранилища и ставит новые
#      (Debian/Ubuntu, Fedora/RHEL, Arch, openSUSE).
#
# Браузеры Firefox и Chrome/Chromium на Linux обычно не читают системное хранилище:
# сертификаты (ca.crt и new_root_ca.crt из рабочей папки) нужно импортировать в них вручную.
#
# Примеры:
#   ./certify-linux.sh.sh rzd.ru job.alfabank.ru     # список = ровно эти сайты
#   ./certify-linux.sh.sh --add online.sberbank.ru   # дописать к сохранённому списку
#   ./certify-linux.sh.sh -f my-sites.txt            # список из файла (по одному на строку)
#   ./certify-linux.sh.sh --list                     # показать сохранённый список
#
set -euo pipefail

# update-ca-certificates и update-ca-trust лежат в sbin, которого может не быть в PATH обычного пользователя
export PATH="$PATH:/usr/sbin:/sbin"

WORKDIR="${MINCIFRY_DIR:-$HOME/mincifry-restricted}"
SITES_FILE="$WORKDIR/sites.txt"
ROOT_CN="Russian Trusted Root CA"
MY_CN="My-Restricted-Root"
ROOT_SUBJ="/C=RU/O=The Ministry of Digital Development and Communications/CN=${ROOT_CN}"

# имена файлов в системном хранилище (на Debian/Ubuntu обязательно расширение .crt)
OUR_CA_NAME="mincifry-restricted-root.crt"
OUR_RU_NAME="mincifry-restricted-russian-root.crt"

die()  { echo "ОШИБКА: $*" >&2; exit 1; }
info() { echo "==> $*"; }
warn() { echo "ВНИМАНИЕ: $*" >&2; }

usage() {
  cat <<'EOF'
Использование: certify-linux.sh.sh [опции] [сайт ...]

Опции:
  -a, --add          добавить сайты к ранее сохранённому списку (по умолчанию список заменяется)
  -f, --file ФАЙЛ    прочитать сайты из файла (по одному на строку, # — комментарий)
  -l, --list         показать сохранённый список и выйти
  -n, --no-install   собрать и проверить сертификаты, но не трогать систему
  -y, --yes          не спрашивать подтверждение
  -h, --help         эта справка

Переменные окружения:
  MINCIFRY_DIR   рабочая папка (по умолчанию ~/mincifry-restricted)
  ROOT_CA        путь к корневому сертификату Минцифры (.cer/.crt/.pem), если скрипт не нашёл его сам
  OPENSSL        путь к openssl (нужен OpenSSL 1.1.1+ с опцией -force_pubkey)

Для каждого сайта автоматически разрешаются и сам домен, и все его поддомены.
Кириллические домены (.рф) указывайте в punycode (например, xn--p1ai).
EOF
}

MODE_ADD=0; ASSUME_YES=0; NO_INSTALL=0; DO_LIST=0
RAW=""

read_list_file() {
  [[ -r "$1" ]] || die "Не могу прочитать файл: $1"
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | tr -d '[:space:]')"
    if [[ -n "$line" ]]; then RAW+="$line"$'\n'; fi
  done < "$1"
  return 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -a|--add)        MODE_ADD=1 ;;
    -f|--file)       shift; [[ $# -gt 0 ]] || die "После -f нужен путь к файлу"; read_list_file "$1" ;;
    -l|--list)       DO_LIST=1 ;;
    -n|--no-install) NO_INSTALL=1 ;;
    -y|--yes)        ASSUME_YES=1 ;;
    -h|--help)       usage; exit 0 ;;
    -*)              die "Неизвестная опция: $1 (см. --help)" ;;
    *)               RAW+="$1"$'\n' ;;
  esac
  shift
done

[[ "$(uname -s)" == "Linux" ]] || die "Этот скрипт рассчитан на Linux. Для macOS используйте mincifry-certs.sh."

if [[ "$EUID" -eq 0 ]]; then
  [[ -z "${SUDO_USER:-}" ]] || die "Не запускайте через sudo: sudo будет вызван только там, где нужно
(иначе файлы в рабочей папке и базы браузеров станут принадлежать root)."
  warn "Скрипт запущен от root: рабочая папка ($WORKDIR) и импорт в браузеры относятся к пользователю root."
fi

# выполнить команду от root (без sudo, если мы и так root)
as_root() {
  if [[ "$EUID" -eq 0 ]]; then "$@"; else sudo "$@"; fi
}

mkdir -p "$WORKDIR"
chmod 700 "$WORKDIR"

if [[ "$DO_LIST" -eq 1 ]]; then
  if [[ -f "$SITES_FILE" ]]; then cat "$SITES_FILE"; else echo "(список пуст)"; fi
  exit 0
fi

# ---------- нормализация и проверка списка сайтов ----------
if [[ "$MODE_ADD" -eq 1 && -f "$SITES_FILE" ]]; then
  RAW="$(cat "$SITES_FILE")"$'\n'"$RAW"
fi

normalize() {
  local d
  d="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  d="${d#http://}"; d="${d#https://}"
  d="${d%%/*}"; d="${d%%:*}"
  d="${d#\*.}"; d="${d#.}"
  printf '%s' "$d"
}

DOMAIN_RE='^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$'
LIST=""
while IFS= read -r line; do
  [[ -n "$line" ]] || continue
  d="$(normalize "$line")"
  [[ "$d" =~ $DOMAIN_RE ]] || die "Некорректный домен: '$line' (для .рф используйте punycode)"
  LIST+="$d"$'\n'
done <<< "$RAW"

LIST="$(printf '%s' "$LIST" | sed '/^$/d' | sort -u)"
[[ -n "$LIST" ]] || { usage; die "Не указано ни одного сайта."; }

# ---------- поиск инструментов и корневого сертификата ----------
find_openssl() {
  local c help
  for c in "${OPENSSL:-}" openssl; do
    [[ -n "$c" ]] || continue
    command -v "$c" >/dev/null 2>&1 || continue
    help="$("$c" x509 -help 2>&1 || true)"
    if grep -q 'force_pubkey' <<<"$help"; then command -v "$c"; return 0; fi
  done
  return 1
}
OSSL="$(find_openssl)" || die "Не найден OpenSSL с поддержкой -force_pubkey (нужна версия 1.1.1 или новее).
Обновите пакет openssl или укажите путь: OPENSSL=/путь/к/openssl $0 ..."

# Принимает сертификат в PEM или в DER (.cer) и записывает PEM в файл $2
to_pem() {
  if grep -q "BEGIN CERTIFICATE" "$1" 2>/dev/null; then
    cp "$1" "$2"
  else
    "$OSSL" x509 -inform DER -in "$1" -out "$2" 2>/dev/null
  fi
}

# Где искать скачанные сертификаты: рабочая папка, папка «Загрузки» (в т.ч. русскоязычная)
SEARCH_DIRS=("$WORKDIR")
for x in "$(xdg-user-dir DOWNLOAD 2>/dev/null || true)" "$HOME/Downloads" "$HOME/Загрузки"; do
  [[ -n "$x" && "$x" != "$HOME" && -d "$x" ]] || continue
  dup=0
  for y in "${SEARCH_DIRS[@]}"; do [[ "$y" == "$x" ]] && dup=1; done
  if [[ "$dup" -eq 0 ]]; then SEARCH_DIRS+=("$x"); fi
done

# Файлы сертификатов Минцифры в этих папках (ГОСТ-версии пропускаем)
cert_candidates() {
  find "${SEARCH_DIRS[@]}" -maxdepth 3 -type f \
    \( -iname '*.cer' -o -iname '*.crt' -o -iname '*.pem' \) 2>/dev/null \
    | grep -iE 'russian|trusted' | grep -vi 'gost' | sort -u || true
}

ROOT_FILE="$WORKDIR/root_ca.pem"   # PEM-копия найденного корня
ROOT_SRC=""

# Ищет среди файлов именно корневой сертификат (по имени субъекта), а не Sub CA
find_root() {
  local c tmp cands
  if [[ -n "${ROOT_CA:-}" ]]; then cands="$ROOT_CA"; else cands="$(cert_candidates)"; fi
  tmp="$(mktemp)"
  while IFS= read -r c; do
    [[ -n "$c" && -f "$c" ]] || continue
    if to_pem "$c" "$tmp" && "$OSSL" x509 -in "$tmp" -noout -subject 2>/dev/null | grep -q "$ROOT_CN"; then
      cp "$tmp" "$ROOT_FILE"; ROOT_SRC="$c"; rm -f "$tmp"; return 0
    fi
  done <<< "$cands"
  rm -f "$tmp"
  return 1
}
find_root || die "Не найден корневой сертификат '$ROOT_CN' (.cer, .crt или .pem).
Скачайте его на https://www.gosuslugi.ru/crt и положите в $WORKDIR или в папку «Загрузки»,
либо укажите путь: ROOT_CA=/путь/к/файлу $0 ...
(Файлы 'Sub CA' и ГОСТ-версии не подходят — нужен именно Root CA.)"

info "OpenSSL:         $OSSL"
info "Корень Минцифры: $ROOT_SRC"
info "Сайты (домен и все поддомены):"
printf '      %s\n' $LIST

# ---------- сборка ----------
cd "$WORKDIR"
LOG="$(mktemp)"
cleanup() { rm -f "$LOG" "$WORKDIR/temp.key" "$WORKDIR/ca.key" "$WORKDIR/ca.srl"; }
trap cleanup EXIT

run_quiet() {
  if ! "$@" >"$LOG" 2>&1; then cat "$LOG" >&2; die "Команда завершилась с ошибкой: $1 $2 $3"; fi
}

rm -f ca.key ca.crt ca.srl new_root_ca.crt temp.key dummy.csr digital-gov.pub cross.conf test-bundle.pem

NC="critical"
for d in $LIST; do NC="$NC, permitted;DNS:$d, permitted;DNS:.$d"; done

info "Создаю собственный корень с ограничением по доменам..."
run_quiet "$OSSL" req -x509 -days 3650 -newkey rsa:4096 -nodes \
  -keyout ca.key -out ca.crt -subj "/CN=$MY_CN" \
  -addext "basicConstraints = critical,CA:true,pathlen:5" \
  -addext "keyUsage = critical,digitalSignature,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier = hash" \
  -addext "nameConstraints = $NC"
chmod 600 ca.key

info "Готовлю заглушку CSR и публичный ключ Минцифры..."
run_quiet "$OSSL" req -new -newkey rsa:4096 -nodes \
  -keyout temp.key -out dummy.csr -subj "/CN=Temporary Dummy CSR"
"$OSSL" x509 -in "$ROOT_FILE" -pubkey -noout > digital-gov.pub

cat > cross.conf <<'EOF'
[ cross_ca_ext ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer
basicConstraints        = critical, CA:true
keyUsage                = critical, digitalSignature, cRLSign, keyCertSign
EOF

info "Переподписываю корень Минцифры своим ограниченным корнем..."
run_quiet "$OSSL" x509 -req -in dummy.csr \
  -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -sha256 \
  -force_pubkey digital-gov.pub -out new_root_ca.crt \
  -extfile cross.conf -extensions cross_ca_ext -subj "$ROOT_SUBJ"

# ключ нам больше не нужен — удаляем, чтобы им нельзя было воспользоваться позже
rm -f ca.key temp.key ca.srl

# ---------- проверка цепочки ----------
info "Проверяю цепочку на ваших сайтах..."
SUBTMP="$(mktemp)"
{
  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    if to_pem "$f" "$SUBTMP" && "$OSSL" x509 -in "$SUBTMP" -noout -subject 2>/dev/null | grep -q "Sub CA"; then
      cat "$SUBTMP"; echo
    fi
  done <<< "$(cert_candidates)"
  cat new_root_ca.crt; echo
  cat ca.crt; echo
} > test-bundle.pem
rm -f "$SUBTMP"

# Проверяем строго по нашему набору: системные каталоги доверия (/etc/ssl/certs) не используем,
# иначе ранее установленный корень без ограничений мог бы скрыть ошибку.
VERIFY_OPTS=(-CAfile test-bundle.pem -no-CApath)
S_HELP="$("$OSSL" s_client -help 2>&1 || true)"
if grep -q -- '-no-CAstore' <<<"$S_HELP"; then VERIFY_OPTS+=(-no-CAstore); fi

TO=()
if command -v timeout >/dev/null 2>&1; then TO=(timeout 20); fi

FAILED=0
for d in $LIST; do
  out="$(${TO[@]+"${TO[@]}"} "$OSSL" s_client -connect "$d:443" -servername "$d" "${VERIFY_OPTS[@]}" </dev/null 2>&1 || true)"
  if grep -q "Verify return code: 0" <<<"$out"; then
    echo "      OK     $d"
  elif grep -q "permitted subtree violation" <<<"$out"; then
    echo "      ОШИБКА $d — сертификат сайта выдан на имена вне вашего списка (смотрите SAN сертификата)"; FAILED=1
  elif grep -q "CONNECTED" <<<"$out"; then
    echo "      ?      $d — соединение есть, но проверка не прошла (возможно, сайт не использует сертификат Минцифры)"; FAILED=1
  else
    echo "      —      $d — не удалось подключиться (нет сети или сайт не отвечает), пропущено"
  fi
done
if [[ "$FAILED" -eq 1 ]]; then
  warn "Часть сайтов не прошла проверку. Если сертификат сайта выдан на другой домен (например, rzd.ru вместо ticket.rzd.ru), добавьте в список этот домен."
fi

printf '%s\n' $LIST > "$SITES_FILE"

if [[ "$NO_INSTALL" -eq 1 ]]; then
  info "Режим --no-install: система не изменена. Файлы лежат в $WORKDIR"
  exit 0
fi

# ---------- определение системного хранилища доверия ----------
ANCHOR_DIR=""; UPDATE_CMD=(); BACKEND=""
detect_trust_backend() {
  local upd
  if upd="$(command -v update-ca-certificates 2>/dev/null)"; then
    if [[ -d /etc/pki/trust/anchors ]]; then                       # openSUSE / SLE
      ANCHOR_DIR=/etc/pki/trust/anchors; UPDATE_CMD=("$upd"); BACKEND="openSUSE"
    else                                                            # Debian / Ubuntu / Mint
      ANCHOR_DIR=/usr/local/share/ca-certificates; UPDATE_CMD=("$upd" --fresh); BACKEND="Debian/Ubuntu"
    fi
  elif upd="$(command -v update-ca-trust 2>/dev/null)"; then
    if [[ -d /etc/pki/ca-trust/source/anchors ]]; then              # Fedora / RHEL / CentOS
      ANCHOR_DIR=/etc/pki/ca-trust/source/anchors; UPDATE_CMD=("$upd"); BACKEND="Fedora/RHEL"
    elif [[ -d /etc/ca-certificates/trust-source/anchors ]]; then   # Arch / Manjaro
      ANCHOR_DIR=/etc/ca-certificates/trust-source/anchors; UPDATE_CMD=("$upd"); BACKEND="Arch"
    else
      return 1
    fi
  else
    return 1
  fi
}
detect_trust_backend || die "Не удалось определить системное хранилище сертификатов (нет update-ca-certificates / update-ca-trust).
Сертификаты собраны в $WORKDIR (ca.crt и new_root_ca.crt): установите их вручную по инструкции вашего дистрибутива."

# Каталоги, где мог остаться оригинальный корень Минцифры (в том числе по статье-первоисточнику)
ANCHOR_SCAN_DIRS=("$ANCHOR_DIR" /usr/local/share/ca-certificates /etc/pki/ca-trust/source/anchors \
  /usr/share/pki/ca-trust-source/anchors /etc/ca-certificates/trust-source/anchors /etc/pki/trust/anchors)

find_foreign_roots() {
  local dir f tmp seen=" "
  tmp="$(mktemp)"
  for dir in "${ANCHOR_SCAN_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    [[ "$seen" == *" $dir "* ]] && continue
    seen+="$dir "
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      case "$(basename "$f")" in "$OUR_CA_NAME"|"$OUR_RU_NAME") continue ;; esac
      if to_pem "$f" "$tmp" && "$OSSL" x509 -in "$tmp" -noout -subject 2>/dev/null | grep -q "$ROOT_CN"; then
        echo "$f"
      fi
    done < <(find "$dir" -maxdepth 1 \( -type f -o -type l \) 2>/dev/null)
  done
  rm -f "$tmp"
}
FOREIGN="$(find_foreign_roots)"

# ---------- установка в системное хранилище ----------
if [[ "$ASSUME_YES" -ne 1 ]]; then
  echo
  echo "Будет изменено системное хранилище доверия ($BACKEND, каталог $ANCHOR_DIR):"
  echo "  - удалены прежние версии: $OUR_CA_NAME, $OUR_RU_NAME (если есть);"
  if [[ -n "$FOREIGN" ]]; then
    echo "  - удалены другие файлы с корнем '$ROOT_CN' (иначе он продолжит действовать без ограничений):"
    printf '      %s\n' $FOREIGN
  fi
  echo "  - установлены новые сертификаты и выполнено: ${UPDATE_CMD[*]}"
  read -r -p "Продолжить? [y/N] " ans
  [[ "$ans" == "y" || "$ans" == "Y" ]] || { info "Отменено. Система не тронута."; exit 0; }
fi

if [[ "$EUID" -ne 0 ]]; then
  command -v sudo >/dev/null 2>&1 || die "Нужны права root: установите sudo или запустите скрипт от root."
  sudo -v
fi

info "Удаляю старые версии из системного хранилища..."
as_root rm -f "$ANCHOR_DIR/$OUR_CA_NAME" "$ANCHOR_DIR/$OUR_RU_NAME"
for f in $FOREIGN; do as_root rm -f "$f"; done

info "Устанавливаю новые сертификаты в $ANCHOR_DIR ..."
as_root mkdir -p "$ANCHOR_DIR"
as_root install -m 0644 "$WORKDIR/ca.crt" "$ANCHOR_DIR/$OUR_CA_NAME"
as_root install -m 0644 "$WORKDIR/new_root_ca.crt" "$ANCHOR_DIR/$OUR_RU_NAME"
as_root "${UPDATE_CMD[@]}"

info "Готово. Список сохранён в $SITES_FILE"
echo "curl, wget и другие программы, использующие системное хранилище, уже работают с новыми сертификатами."
echo
echo "Firefox и Chrome/Chromium на Linux системное хранилище обычно НЕ читают: у них свои базы."
echo "Импортируйте в браузер вручную (подробности — в README):"
echo "  $WORKDIR/ca.crt"
echo "  $WORKDIR/new_root_ca.crt"
echo "Если вы раньше вручную импортировали в браузер оригинальные сертификаты Минцифры, удалите их там:"
echo "оригинальный корень без ограничений обойдёт защиту."
echo
echo "Программы со своим хранилищем (Python с certifi, Java, Node.js и т.п.) системное хранилище по умолчанию не используют."