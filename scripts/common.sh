# shellcheck shell=bash
# scripts/common.sh — общая часть скриптов scripts/linux/*.sh и scripts/macos/*.sh.
# Подключается через `source` (сам по себе не запускается). Платформенный скрипт должен до подключения задать
# SCRIPT_DIR и SCRIPT_NAME, а после — определить функции-«хуки»:
#   certify.sh:   platform_check, platform_find_openssl, platform_prepare, platform_confirm_text, platform_install, platform_done
#                 (+ переменная OPENSSL_HINT; необязательно: USAGE_ENV — строка про переменные окружения для --help)
#   uninstall.sh: platform_check, platform_uninstall_certs

ROOT_CN="Russian Trusted Root CA"
MY_CN="My-Restricted-Root"
ROOT_SUBJ="/C=RU/O=The Ministry of Digital Development and Communications/CN=${ROOT_CN}"
DOMAIN_RE='^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$'
VERIFY_MAX=5          # сколько сайтов из списка проверять по сети

REPO_DIR="$(cd "$SCRIPT_DIR/../.." && pwd -P)"

die()  { echo "ОШИБКА: $*" >&2; exit 1; }
warn() { echo "ВНИМАНИЕ: $*" >&2; }
say()  { echo "$*"; }

MODE_ADD=0; ASSUME_YES=0; NO_INSTALL=0; DO_LIST=0; VERBOSE=0
RAW=""
WORKDIR="$REPO_DIR/certs"        # корень Минцифры лежит здесь же; сюда пишутся и наши сертификаты
SITES_FILE="$WORKDIR/sites.txt"
TMPD=""; ROOT_FILE=""; ROOT_SRC=""; LOG=""

cleanup() { if [[ -n "$TMPD" ]]; then rm -rf "$TMPD"; fi; }

# путь для вывода: внутри репозитория показываем относительный
short() { local p="$1"; if [[ "$p" == "$REPO_DIR/"* ]]; then p="${p#"$REPO_DIR"/}"; fi; printf '%s' "$p"; }

usage() {
  local env_line=""
  if [[ -n "${USAGE_ENV:-}" ]]; then env_line="Переменные окружения: $USAGE_ENV"$'\n\n'; fi
  cat <<EOF
Использование: $SCRIPT_NAME [опции] [сайт ...]

Опции:
  -a, --add            добавить сайты к ранее сохранённому списку (по умолчанию список заменяется)
  -f, --file ФАЙЛ      прочитать сайты из файла (по одному на строку, # — комментарий)
  -l, --list           показать сохранённый список и выйти
  -n, --no-install     только собрать и проверить сертификаты, систему не менять
  -y, --yes            не спрашивать подтверждение установки
  -v, --verbose        показывать результат проверки по каждому сайту
  -h, --help           эта справка

${env_line}Сертификаты и список сайтов (sites.txt) записываются в папку certs/ репозитория.
Для каждого сайта разрешаются и сам домен, и все его поддомены.
Кириллические домены (.рф) указывайте в punycode (например, xn--p1ai).
EOF
}

# Печатает «чистые» строки списка из файла (без комментариев и пробелов)
list_file_lines() {
  local line
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(printf '%s' "$line" | tr -d '[:space:]')"
    if [[ -n "$line" ]]; then printf '%s\n' "$line"; fi
  done < "$1"
  return 0
}

parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -a|--add)        MODE_ADD=1 ;;
      -f|--file)       shift; [[ $# -gt 0 ]] || die "После -f нужен путь к файлу"
                       [[ -r "$1" ]] || die "Не могу прочитать файл: $1"
                       RAW+="$(list_file_lines "$1")"$'\n' ;;
      -l|--list)       DO_LIST=1 ;;
      -n|--no-install) NO_INSTALL=1 ;;
      -y|--yes)        ASSUME_YES=1 ;;
      -v|--verbose)    VERBOSE=1 ;;
      -h|--help)       usage; exit 0 ;;
      -*)              die "Неизвестная опция: $1 (см. --help)" ;;
      *)               RAW+="$1"$'\n' ;;
    esac
    shift
  done
}

normalize_domain() {
  local d
  d="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  d="${d#http://}"; d="${d#https://}"
  d="${d%%/*}"; d="${d%%:*}"
  d="${d#\*.}"; d="${d#.}"
  printf '%s' "$d"
}

LIST=""; N_SITES=0
resolve_sites() {
  local raw="" line d
  if [[ "$MODE_ADD" -eq 1 && -f "$SITES_FILE" ]]; then raw+="$(cat "$SITES_FILE")"$'\n'; fi
  raw+="$RAW"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    d="$(normalize_domain "$line")"
    [[ "$d" =~ $DOMAIN_RE ]] || die "Некорректный домен: '$line' (для .рф используйте punycode)"
    LIST+="$d"$'\n'
  done <<< "$raw"
  LIST="$(printf '%s' "$LIST" | sed '/^$/d' | sort -u)"
  [[ -n "$LIST" ]] || die "Не указано ни одного сайта: передайте домены или файл со списком (-f), см. --help."
  N_SITES="$(printf '%s\n' "$LIST" | wc -l | tr -d ' ')"
}

# Принимает сертификат в PEM или в DER (.cer) и записывает PEM в файл $2
to_pem() {
  if grep -q "BEGIN CERTIFICATE" "$1" 2>/dev/null; then
    cp "$1" "$2"
  else
    "$OSSL" x509 -inform DER -in "$1" -out "$2" 2>/dev/null
  fi
}

# Где искать сертификаты Минцифры: папка certs/ репозитория
SEARCH_DIRS=()
add_search_dir() {
  local x="$1" y
  [[ -n "$x" && "$x" != "$HOME" && -d "$x" ]] || return 0
  for y in ${SEARCH_DIRS[@]+"${SEARCH_DIRS[@]}"}; do
    if [[ "$y" == "$x" ]]; then return 0; fi
  done
  SEARCH_DIRS+=("$x")
}

# Файлы сертификатов Минцифры в этих папках (ГОСТ-версии пропускаем); порядок папок сохраняется
cert_candidates() {
  [[ ${#SEARCH_DIRS[@]} -gt 0 ]] || return 0
  find "${SEARCH_DIRS[@]}" -maxdepth 3 -type f \
    \( -iname '*.cer' -o -iname '*.crt' -o -iname '*.pem' \) 2>/dev/null \
    | grep -iE 'russian|trusted' | grep -vi 'gost' || true
}

# Ищет среди файлов именно корневой сертификат (по имени субъекта), а не Sub CA
find_root() {
  local c tmp cands
  cands="$(cert_candidates)"
  tmp="$TMPD/candidate.pem"
  while IFS= read -r c; do
    [[ -n "$c" && -f "$c" ]] || continue
    if to_pem "$c" "$tmp" && "$OSSL" x509 -in "$tmp" -noout -subject 2>/dev/null | grep -q "$ROOT_CN"; then
      cp "$tmp" "$ROOT_FILE"; ROOT_SRC="$c"; return 0
    fi
  done <<< "$cands"
  return 1
}

run_quiet() {
  if ! "$@" >"$LOG" 2>&1; then cat "$LOG" >&2; die "Команда завершилась с ошибкой: $1 $2 $3"; fi
}

# Сборка: все промежуточные файлы живут во временной папке и удаляются при выходе;
# в рабочую папку попадают только ca.crt, new_root_ca.crt и sites.txt.
build_certs() {
  say "Генерирую сертификаты..."
  cd "$TMPD"
  local nc="critical" d
  for d in $LIST; do nc="$nc, permitted;DNS:$d, permitted;DNS:.$d"; done

  run_quiet "$OSSL" req -x509 -days 3650 -newkey rsa:4096 -nodes \
    -keyout ca.key -out ca.crt -subj "/CN=$MY_CN" \
    -addext "basicConstraints = critical,CA:true,pathlen:5" \
    -addext "keyUsage = critical,digitalSignature,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier = hash" \
    -addext "nameConstraints = $nc"
  run_quiet "$OSSL" req -new -newkey rsa:4096 -nodes \
    -keyout temp.key -out dummy.csr -subj "/CN=Temporary Dummy CSR"
  "$OSSL" x509 -in "$ROOT_FILE" -pubkey -noout > digital-gov.pub

  # Ограничения по доменам записываются и в переподписанный сертификат: некоторые клиенты (например, curl)
  # принимают «неполную цепочку» и считают его точкой доверия, тогда ограничения только в вашем корне не сработали бы.
  cat > cross.conf <<CROSS_EOF
[ cross_ca_ext ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer
basicConstraints        = critical, CA:true
keyUsage                = critical, digitalSignature, cRLSign, keyCertSign
nameConstraints         = $nc
CROSS_EOF

  run_quiet "$OSSL" x509 -req -in dummy.csr \
    -CA ca.crt -CAkey ca.key -CAcreateserial -days 3650 -sha256 \
    -force_pubkey digital-gov.pub -out new_root_ca.crt \
    -extfile cross.conf -extensions cross_ca_ext -subj "$ROOT_SUBJ"

  rm -f ca.key temp.key ca.srl      # закрытый ключ больше не нужен
  mkdir -p "$WORKDIR" || die "Не удалось создать папку: $WORKDIR"
  cp ca.crt new_root_ca.crt "$WORKDIR/"
  printf '%s\n' $LIST > "$SITES_FILE"
}

# Проверка по сети: первые VERIFY_MAX сайтов списка, строго по нашему набору сертификатов
# (системные каталоги доверия не используем: ранее установленный корень без ограничений мог бы скрыть ошибку).
verify_sites() {
  local bundle="$TMPD/test-bundle.pem" subtmp="$TMPD/sub.pem" f
  {
    while IFS= read -r f; do
      [[ -n "$f" ]] || continue
      if to_pem "$f" "$subtmp" && "$OSSL" x509 -in "$subtmp" -noout -subject 2>/dev/null | grep -q "Sub CA"; then
        cat "$subtmp"; echo
      fi
    done <<< "$(cert_candidates)"
    cat "$TMPD/new_root_ca.crt"; echo
    cat "$TMPD/ca.crt"; echo
  } > "$bundle"

  local opts=(-CAfile "$bundle" -no-CApath) s_help
  s_help="$("$OSSL" s_client -help 2>&1 || true)"
  if grep -q -- '-no-CAstore' <<<"$s_help"; then opts+=(-no-CAstore); fi

  local to=()
  if command -v timeout >/dev/null 2>&1; then to=(timeout 10)
  elif command -v perl >/dev/null 2>&1; then to=(perl -e 'alarm shift; exec @ARGV' 10); fi

  local sample d out checked=0 ok=0 nolink=0 bad=0
  sample="$(printf '%s\n' "$LIST" | sed -n "1,${VERIFY_MAX}p")"
  while IFS= read -r d; do
    [[ -n "$d" ]] || continue
    checked=$((checked + 1))
    out="$(${to[@]+"${to[@]}"} "$OSSL" s_client -connect "$d:443" -servername "$d" "${opts[@]}" </dev/null 2>&1 || true)"
    if grep -q "Verify return code: 0" <<<"$out"; then
      ok=$((ok + 1)); if [[ "$VERBOSE" -eq 1 ]]; then echo "  OK      $d"; fi
    elif grep -q "permitted subtree violation" <<<"$out"; then
      bad=$((bad + 1)); echo "  ОШИБКА  $d: сертификат выдан на имена вне списка (проверьте SAN и добавьте нужный домен)"
    elif grep -q "CONNECTED" <<<"$out"; then
      bad=$((bad + 1)); echo "  ОШИБКА  $d: соединение есть, но проверка не прошла (возможно, сайт не на сертификате Минцифры)"
    else
      nolink=$((nolink + 1)); if [[ "$VERBOSE" -eq 1 ]]; then echo "  нет связи  $d"; fi
    fi
  done <<< "$sample"
  say "Проверено $checked из $N_SITES: OK $ok, нет связи $nolink, ошибок $bad"
}

# ---------- общее для Linux ----------
OUR_CA_NAME="mincifry-restricted-root.crt"            # на Debian/Ubuntu обязательно расширение .crt
OUR_RU_NAME="mincifry-restricted-russian-root.crt"
ANCHOR_DIR=""; UPDATE_CMD=(); BACKEND=""

as_root() { if [[ "$EUID" -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

check_linux() {
  [[ "$(uname -s)" == "Linux" ]] || die "Этот скрипт рассчитан на Linux. Для macOS используйте scripts/macos/."
  if [[ "$EUID" -eq 0 && -n "${SUDO_USER:-}" ]]; then die "Не запускайте через sudo: sudo будет вызван только там, где нужно."; fi
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

# ---------- общее для macOS ----------
KEYCHAIN="/Library/Keychains/System.keychain"

check_macos() {
  [[ "$(uname -s)" == "Darwin" ]] || die "Скрипт рассчитан на macOS. Для Linux используйте scripts/linux/."
  [[ "$EUID" -ne 0 ]] || die "Не запускайте через sudo: sudo будет вызван только там, где нужно."
}

remove_cert() {   # удаляет из системной связки все сертификаты с таким именем
  local cn="$1" n=0
  while sudo security delete-certificate -c "$cn" "$KEYCHAIN" >/dev/null 2>&1; do
    n=$((n + 1)); if [[ "$n" -ge 10 ]]; then break; fi
  done
  return 0
}

# ---------- удаление (uninstall.sh) ----------
uninstall_usage() {
  cat <<EOF
Использование: bash <папка проекта>/scripts/<ОС>/uninstall.sh [опции]

Без опций скрипт спросит, что удалить.
  -c, --certs   удалить только сертификаты из системы
  -a, --all     удалить всё: сертификаты и папку проекта целиком
  -y, --yes     не спрашивать подтверждение
  -h, --help    эта справка

Для --all запускайте скрипт из папки выше проекта (не изнутри него).
EOF
}

# Перед удалением папки проверяем, что это действительно наш проект и мы не стоим внутри неё
guard_project_dir() {
  local here; here="$(pwd -P)"
  [[ -f "$REPO_DIR/scripts/common.sh" && -d "$REPO_DIR/certs" ]] || die "Папка $REPO_DIR не похожа на проект, удалять не буду."
  case "$REPO_DIR" in /|"$HOME"|"") die "Отказываюсь удалять $REPO_DIR." ;; esac
  case "$here/" in "$REPO_DIR"/*) die "Вы находитесь внутри папки проекта. Перейдите выше (cd ..) и запустите скрипт снова." ;; esac
}

uninstall_main() {
  local mode="" choice ans
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -c|--certs) mode=certs ;;
      -a|--all)   mode=all ;;
      -y|--yes)   ASSUME_YES=1 ;;
      -h|--help)  uninstall_usage; exit 0 ;;
      *)          die "Неизвестная опция: $1 (см. --help)" ;;
    esac
    shift
  done
  platform_check
  TMPD="$(mktemp -d)"; LOG="$TMPD/log"; trap cleanup EXIT

  if [[ -z "$mode" ]]; then
    [[ -t 0 ]] || die "Нужен терминал или опция --certs / --all (см. --help)."
    echo "Что удалить?"
    echo "  1) сертификаты из системы"
    echo "  2) весь проект: сертификаты и папку $REPO_DIR"
    read -r -p "Выбор [1/2]: " choice || choice=""
    case "$choice" in 1) mode=certs ;; 2) mode=all ;; *) say "Отменено."; exit 0 ;; esac
  fi
  if [[ "$mode" == "all" ]]; then guard_project_dir; fi

  if [[ "$ASSUME_YES" -ne 1 ]]; then
    [[ -t 0 ]] || die "Нужен терминал для подтверждения: добавьте -y."
    if [[ "$mode" == "all" ]]; then say "Будут удалены сертификаты из системы и папка $REPO_DIR (вместе с этим скриптом)."
    else say "Будут удалены сертификаты из системы."; fi
    read -r -p "Вы уверены? [y/N] " ans || ans=""
    [[ "$ans" == "y" || "$ans" == "Y" ]] || { say "Отменено."; exit 0; }
  fi

  platform_uninstall_certs
  if [[ "$mode" == "all" ]]; then
    rm -rf "$REPO_DIR"
    say "Папка проекта удалена: $REPO_DIR"
  fi
}

mincifry_main() {
  parse_args "$@"
  platform_check

  if [[ "$DO_LIST" -eq 1 ]]; then
    if [[ -f "$SITES_FILE" ]]; then cat "$SITES_FILE"; else echo "(список пуст)"; fi
    exit 0
  fi

  resolve_sites
  TMPD="$(mktemp -d)"; LOG="$TMPD/log"; ROOT_FILE="$TMPD/root_ca.pem"
  trap cleanup EXIT

  OSSL="$(platform_find_openssl)" || die "$OPENSSL_HINT"
  add_search_dir "$REPO_DIR/certs"
  find_root || die "Не найден корневой сертификат '$ROOT_CN'.
Ожидался файл в папке certs/ репозитория ($REPO_DIR/certs). Скачайте его на https://www.gosuslugi.ru/crt
(.cer, .crt или .pem) и положите туда.
(Файлы 'Sub CA' и ГОСТ-версии не подходят — нужен именно Root CA.)"

  say "Корень Минцифры: $(short "$ROOT_SRC")"
  if [[ "$N_SITES" -le "$VERIFY_MAX" ]]; then
    say "Сайтов: $N_SITES ($(printf '%s' "$LIST" | tr '\n' ',' | sed 's/,/, /g; s/, $//'))"
  else
    say "Сайтов: $N_SITES"
  fi

  build_certs
  verify_sites

  if [[ "$NO_INSTALL" -eq 1 ]]; then
    say "Сертификаты собраны в $(short "$WORKDIR"), система не изменена (--no-install)."
    exit 0
  fi

  platform_prepare
  if [[ "$ASSUME_YES" -ne 1 ]]; then
    [[ -t 0 ]] || die "Нужен терминал для подтверждения: добавьте -y, чтобы продолжить без вопросов."
    echo
    platform_confirm_text
    local ans
    read -r -p "Продолжить? [y/N] " ans || ans=""
    [[ "$ans" == "y" || "$ans" == "Y" ]] || { say "Отменено, система не тронута. Сертификаты лежат в $(short "$WORKDIR")."; exit 0; }
  fi
  platform_install
  platform_done
}
