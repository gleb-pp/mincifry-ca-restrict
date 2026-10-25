# shellcheck shell=bash
# scripts/lib/common.sh — общая часть certify-linux.sh и certify-macos.sh.
# Подключается через `source` (сам по себе не запускается). Платформенный скрипт должен до подключения задать
# SCRIPT_DIR и SCRIPT_NAME, а после — определить функции-«хуки»:
#   platform_check, platform_find_openssl, platform_prepare, platform_confirm_text, platform_install, platform_done
# и переменную OPENSSL_HINT (подсказка, если OpenSSL не найден). Необязательно: platform_search_dirs, USAGE_EXTRA.

ROOT_CN="Russian Trusted Root CA"
MY_CN="My-Restricted-Root"
ROOT_SUBJ="/C=RU/O=The Ministry of Digital Development and Communications/CN=${ROOT_CN}"
DOMAIN_RE='^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$'
VERIFY_MAX=5          # сколько сайтов из списка проверять по сети

REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

die()  { echo "ОШИБКА: $*" >&2; exit 1; }
warn() { echo "ВНИМАНИЕ: $*" >&2; }
say()  { echo "$*"; }

MODE_ADD=0; ASSUME_YES=0; NO_INSTALL=0; DO_LIST=0; POPULAR=0; VERBOSE=0
RAW=""
WORKDIR="${MINCIFRY_DIR:-$REPO_DIR/certs}"
ROOT_CA="${ROOT_CA:-}"
TMPD=""; ROOT_FILE=""; ROOT_SRC=""; LOG=""

cleanup() { if [[ -n "$TMPD" ]]; then rm -rf "$TMPD"; fi; }

# путь для вывода: внутри репозитория показываем относительный
short() { local p="$1"; if [[ "$p" == "$REPO_DIR/"* ]]; then p="${p#"$REPO_DIR"/}"; fi; printf '%s' "$p"; }

usage() {
  cat <<EOF
Использование: $SCRIPT_NAME [опции] [сайт ...]

Опции:
  -p, --popular        взять за основу готовый список популярных российских сайтов (popular.txt);
                       свои сайты можно добавить к нему
  -a, --add            добавить сайты к ранее сохранённому списку (по умолчанию список заменяется)
  -f, --file ФАЙЛ      прочитать сайты из файла (по одному на строку, # — комментарий)
  -l, --list           показать сохранённый список и выйти
  -w, --workdir ПУТЬ   куда записать сертификаты (по умолчанию папка certs/ репозитория)
  -r, --root-ca ПУТЬ   корневой сертификат Минцифры (по умолчанию из папки certs/ репозитория)
  -n, --no-install     только собрать и проверить сертификаты, систему не менять
  -y, --yes            не спрашивать подтверждение установки
  -v, --verbose        показывать результат проверки по каждому сайту
  -h, --help           эта справка

Переменные окружения (флаги важнее): MINCIFRY_DIR (= --workdir), ROOT_CA (= --root-ca)${USAGE_EXTRA:-}

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
      -p|--popular)    POPULAR=1 ;;
      -a|--add)        MODE_ADD=1 ;;
      -f|--file)       shift; [[ $# -gt 0 ]] || die "После -f нужен путь к файлу"
                       [[ -r "$1" ]] || die "Не могу прочитать файл: $1"
                       RAW+="$(list_file_lines "$1")"$'\n' ;;
      -l|--list)       DO_LIST=1 ;;
      -w|--workdir)    shift; [[ $# -gt 0 ]] || die "После --workdir нужен путь к папке"; WORKDIR="$1" ;;
      -r|--root-ca)    shift; [[ $# -gt 0 ]] || die "После --root-ca нужен путь к файлу"; ROOT_CA="$1" ;;
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

# Путь к рабочей папке: раскрываем ~ и делаем абсолютным
normalize_workdir() {
  case "$WORKDIR" in "~"|"~/"*) WORKDIR="$HOME${WORKDIR#\~}" ;; esac
  case "$WORKDIR" in /*) ;; *) WORKDIR="$PWD/$WORKDIR" ;; esac
  if [[ "$WORKDIR" != "/" ]]; then WORKDIR="${WORKDIR%/}"; fi
  SITES_FILE="$WORKDIR/sites.txt"
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
  if [[ "$POPULAR" -eq 1 ]]; then
    [[ -r "$REPO_DIR/popular.txt" ]] || die "Не найден список популярных сайтов: $REPO_DIR/popular.txt"
    raw+="$(list_file_lines "$REPO_DIR/popular.txt")"$'\n'
  fi
  raw+="$RAW"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    d="$(normalize_domain "$line")"
    [[ "$d" =~ $DOMAIN_RE ]] || die "Некорректный домен: '$line' (для .рф используйте punycode)"
    LIST+="$d"$'\n'
  done <<< "$raw"
  LIST="$(printf '%s' "$LIST" | sed '/^$/d' | sort -u)"
  [[ -n "$LIST" ]] || die "Не указано ни одного сайта: передайте домены или флаг --popular (см. --help)."
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

# Где искать сертификаты Минцифры: сначала certs/ репозитория, затем запасные варианты
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
  if [[ -n "$ROOT_CA" ]]; then cands="$ROOT_CA"; else cands="$(cert_candidates)"; fi
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

mincifry_main() {
  parse_args "$@"
  normalize_workdir
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
  add_search_dir "$WORKDIR"
  add_search_dir "$HOME/Downloads"
  if declare -F platform_search_dirs >/dev/null; then platform_search_dirs; fi
  find_root || die "Не найден корневой сертификат '$ROOT_CN'.
Ожидался файл в папке certs/ репозитория ($REPO_DIR/certs). Скачайте его на https://www.gosuslugi.ru/crt
(.cer, .crt или .pem) и положите туда, либо укажите путь: --root-ca /путь/к/файлу
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
