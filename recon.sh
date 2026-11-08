#!/usr/bin/env bash
#
# recon.sh - subfinder -> httpx -> katana -> nuclei + JS extraction
#
# Usage:
#   ./recon.sh -d example.com
#   ./recon.sh -d example.com -o /data/bb -H 'X-Bug-Bounty: myhandle'
#   ./recon.sh -d example.com --skip-nuclei --force
#
# Output layout (stable per target, so reruns append/refresh):
#   <out>/<domain>/
#   ├── 00-meta/     run info, summary, versions
#   ├── 01-subs/     subfinder results + merged list
#   ├── 02-http/     httpx results, live urls, status/tech breakdown
#   ├── 03-urls/     katana crawl, params, merged urls
#   ├── 04-js/       js urls, downloaded files, endpoints, secrets
#   ├── 05-nuclei/   nuclei findings (jsonl + readable txt)
#   └── logs/        per-stage logs
#
set -uo pipefail

VERSION="1.0.0"

# ---------------------------------------------------------------- defaults --
DOMAIN=""
OUT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/recon"
HEADER=""
THREADS=50
RATE_LIMIT=150
DEPTH=3
SEVERITY="critical,high,medium"
NUCLEI_ON_URLS=0
SKIP_JS=0
SKIP_NUCLEI=0
FORCE=0

# ------------------------------------------------------------------ colors --
if [[ -t 1 ]]; then
  C_R=$'\033[31m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_B=$'\033[34m'; C_N=$'\033[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_N=""
fi

log()  { printf '%s[*]%s %s\n' "$C_B" "$C_N" "$*"; }
ok()   { printf '%s[+]%s %s\n' "$C_G" "$C_N" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_Y" "$C_N" "$*" >&2; }
die()  { printf '%s[x]%s %s\n' "$C_R" "$C_N" "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
recon.sh - subfinder -> httpx -> katana -> nuclei + JS extraction

Usage:
  ./recon.sh -d example.com
  ./recon.sh -d example.com -o /data/bb -H 'X-Bug-Bounty: myhandle'
  ./recon.sh -d example.com --skip-nuclei --force

Output layout (stable per target, so reruns append/refresh):
  <out>/<domain>/
  |-- 00-meta/     run info, summary, versions
  |-- 01-subs/     subfinder results + merged list
  |-- 02-http/     httpx results, live urls, status/tech breakdown
  |-- 03-urls/     katana crawl, params, merged urls
  |-- 04-js/       js urls, downloaded files, endpoints, secrets
  |-- 05-nuclei/   nuclei findings (jsonl + readable txt)
  `-- logs/        per-stage logs
EOF
  cat <<'EOF'

Options:
  -d, --domain <domain>      Target root domain (required)
  -o, --out <dir>            Output root directory (default: ./recon)
  -H, --header <header>      Extra header for httpx/katana/nuclei (repeatable)
  -t, --threads <n>          Concurrency (default: 50)
  -r, --rate-limit <n>       Requests/sec for katana+nuclei (default: 150)
      --depth <n>            Katana crawl depth (default: 3)
      --severity <list>      Nuclei severities (default: critical,high,medium)
      --nuclei-urls          Run nuclei on all discovered URLs, not just hosts
      --skip-js              Skip JS download/extraction
      --skip-nuclei          Skip nuclei
      --force                Re-run stages even if output exists
  -h, --help                 Show this help
EOF
}

# ------------------------------------------------------------------- parse --
ORIG_ARGS="$*"
HDRS=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d|--domain)     DOMAIN="${2:-}"; shift 2 ;;
    -o|--out)        OUT_ROOT="${2:-}"; shift 2 ;;
    -H|--header)     HDRS+=("${2:-}"); shift 2 ;;
    -t|--threads)    THREADS="${2:-}"; shift 2 ;;
    -r|--rate-limit) RATE_LIMIT="${2:-}"; shift 2 ;;
    --depth)         DEPTH="${2:-}"; shift 2 ;;
    --severity)      SEVERITY="${2:-}"; shift 2 ;;
    --nuclei-urls)   NUCLEI_ON_URLS=1; shift ;;
    --skip-js)       SKIP_JS=1; shift ;;
    --skip-nuclei)   SKIP_NUCLEI=1; shift ;;
    --force)         FORCE=1; shift ;;
    -h|--help)       usage; exit 0 ;;
    *)               die "Unknown option: $1 (try --help)" ;;
  esac
done

[[ -n "$DOMAIN" ]] || { usage; die "Missing required -d/--domain"; }
DOMAIN="${DOMAIN#\*.}"; DOMAIN="${DOMAIN#http://}"; DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN%%/*}"
[[ "$DOMAIN" == *.* ]] || die "That doesn't look like a domain: $DOMAIN"

# ---------------------------------------------------------------- toolchain --
need() { command -v "$1" >/dev/null 2>&1 || die "Missing '$1'. Install it: $2"; }

# PD httpx is often installed as httpx-toolkit (Debian/Ubuntu) to avoid the
# Python httpx CLI. Pick whichever supports PD flags.
detect_httpx() {
  local c help
  for c in httpx-toolkit httpx; do
    command -v "$c" >/dev/null 2>&1 || continue
    help="$("$c" -h 2>&1)" || true
    if [[ "$help" == *"-status-code"* && "$help" == *"-threads"* ]]; then
      printf '%s' "$c"; return 0
    fi
  done
  return 1
}

need subfinder "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
need katana     "go install -v github.com/projectdiscovery/katana/cmd/katana@latest"
need nuclei     "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
HTTPX="$(detect_httpx)" || die "ProjectDiscovery httpx not found (install httpx-toolkit)"
HAS_JQ=0; command -v jq >/dev/null 2>&1 && HAS_JQ=1

KATANA_JSLUICE=0
KATANA_FS=()
KATANA_HELP="$(katana -h 2>/dev/null)" || true
[[ "$KATANA_HELP" == *"-jsluice"* ]] && KATANA_JSLUICE=1
[[ "$KATANA_HELP" == *"-field-scope"* ]] && KATANA_FS=(-fs rdn)

SF_VER="$(subfinder -version 2>&1 | awk '/Version/{print $NF; exit}')"
HX_VER="$("$HTTPX" -version 2>&1 | awk '/Version/{print $NF; exit}')"
KT_VER="$(katana -version 2>&1 | awk '/Version/{print $NF; exit}')"
NC_VER="$(nuclei -version 2>&1 | awk '/Version/{print $NF; exit}')"

# ------------------------------------------------------------------- layout --
SAFE_DOMAIN="${DOMAIN//[^a-zA-Z0-9._-]/_}"
OUT="$OUT_ROOT/$SAFE_DOMAIN"
D_META="$OUT/00-meta"
D_SUBS="$OUT/01-subs"
D_HTTP="$OUT/02-http"
D_URLS="$OUT/03-urls"
D_JS="$OUT/04-js"
D_JS_FILES="$D_JS/files"
D_NUCLEI="$OUT/05-nuclei"
D_LOGS="$OUT/logs"
mkdir -p "$D_META" "$D_SUBS" "$D_HTTP" "$D_URLS" "$D_JS_FILES" "$D_NUCLEI" "$D_LOGS"

RUN_TS="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="$D_LOGS/run-$RUN_TS.log"
exec > >(tee -a "$LOG") 2>&1

log "Target:   $DOMAIN"
log "Output:   $OUT"
log "Run id:   $RUN_TS"
log "httpx:    $HTTPX ($HX_VER) | katana: $KT_VER | nuclei: $NC_VER"

{
  echo "target=$DOMAIN"
  echo "run_id=$RUN_TS"
  echo "started_utc=$(date -u +%FT%TZ)"
  echo "argv=$ORIG_ARGS"
  echo "subfinder=$SF_VER"
  echo "httpx=$HTTPX $HX_VER"
  echo "katana=$KT_VER"
  echo "nuclei=$NC_VER"
} > "$D_META/run-$RUN_TS.env"

HDR_ARGS=()
for h in "${HDRS[@]:-}"; do [[ -n "$h" ]] && HDR_ARGS+=(-H "$h"); done

have() { [[ -s "$1" && "$FORCE" -eq 0 ]]; }
lines() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

# Publish a temp file only if non-empty, so interrupted stages don't look done.
publish() { # publish <tmp> <final>
  if [[ -s "$1" ]]; then mv -f "$1" "$2"; else rm -f "$1"; warn "No results for $(basename "$2")"; fi
}

# ------------------------------------------------------------ 1. subdomains --
stage_subs() {
  local final="$D_SUBS/subfinder.txt"
  if have "$final"; then log "subfinder: reusing $(lines "$final") subs"; return; fi
  log "subfinder: enumerating passive subdomains..."
  local tmp="$final.tmp"
  subfinder -d "$DOMAIN" -all -recursive -silent -o "$tmp" >/dev/null \
    || warn "subfinder exited non-zero"
  publish "$tmp" "$final"
  { cat "$final" 2>/dev/null; echo "$DOMAIN"; } | tr '[:upper:]' '[:lower:]' \
    | sed '/^$/d' | sort -u > "$D_SUBS/all-subs.txt"
  ok "subdomains: $(lines "$D_SUBS/all-subs.txt")"
}

# --------------------------------------------------------------- 2. httpx --
stage_http() {
  local raw="$D_HTTP/httpx.jsonl" final="$D_HTTP/live-urls.txt"
  if have "$final"; then log "httpx: reusing $(lines "$final") live hosts"; return; fi
  log "httpx: probing $(lines "$D_SUBS/all-subs.txt") hosts..."
  local tmp="$raw.tmp"
  "$HTTPX" -l "$D_SUBS/all-subs.txt" "${HDR_ARGS[@]}" \
    -silent -threads "$THREADS" -timeout 10 -retries 2 \
    -status-code -title -tech-detect -web-server -cdn -follow-redirects \
    -json -o "$tmp" >/dev/null || warn "httpx exited non-zero"
  publish "$tmp" "$raw"

  if [[ "$HAS_JQ" -eq 1 && -s "$raw" ]]; then
    jq -r 'select(.url) | [.url, (.status_code|tostring), (.title // ""),
           ((.tech // [])|join(",")), (.webserver // "")] | @tsv' "$raw" \
      | sort -u > "$D_HTTP/httpx.txt"
    jq -r 'select(.url) | .url' "$raw" | sort -u > "$final"
    awk -F'\t' '{print $2}' "$D_HTTP/httpx.txt" | sort | uniq -c | sort -rn \
      > "$D_HTTP/status-codes.txt"
    jq -r 'select(.url) | [.url, ((.tech // [])|join(","))] | @tsv' "$raw" \
      | awk -F'\t' 'length($2)' | sort -u > "$D_HTTP/tech.txt"
  elif [[ -s "$raw" ]]; then
    # jq-less fallback: scrape the url field from jsonl
    grep -o '"url":"[^"]*"' "$raw" | cut -d'"' -f4 | sort -u > "$final"
    cp "$final" "$D_HTTP/httpx.txt"
  fi
  ok "live hosts: $(lines "$final")"
}

# --------------------------------------------------------------- 3. katana --
stage_urls() {
  local final="$D_URLS/katana.txt"
  local extra=()
  [[ "$KATANA_JSLUICE" -eq 1 ]] && extra+=(-jsluice)
  if [[ ! -s "$D_HTTP/live-urls.txt" ]]; then
    warn "katana: no live hosts to crawl"; : > "$D_URLS/all-urls.txt"; return
  fi
  if have "$final"; then log "katana: reusing $(lines "$final") urls"; else
    log "katana: crawling $(lines "$D_HTTP/live-urls.txt") hosts (depth $DEPTH)..."
    local tmp="$final.tmp"
    katana -list "$D_HTTP/live-urls.txt" "${HDR_ARGS[@]}" \
      -silent -d "$DEPTH" -jc -kf all "${extra[@]}" "${KATANA_FS[@]}" \
      -c "$THREADS" -p 10 -rl "$RATE_LIMIT" \
      -ef woff,woff2,css,png,jpg,jpeg,gif,svg,ico,ttf,eot,mp4,webp \
      -o "$tmp" >/dev/null || warn "katana exited non-zero"
    publish "$tmp" "$final"
  fi

  # Merge everything we know about into one URL list.
  cat "$D_URLS"/katana.txt "$D_HTTP/live-urls.txt" 2>/dev/null \
    | grep -E '^https?://' | sed '/^$/d' | sort -u > "$D_URLS/all-urls.txt"
  grep -E '\?' "$D_URLS/all-urls.txt" | sort -u > "$D_URLS/params.txt" || true
  grep -E '/api/|/v[0-9]+/|/graphql|swagger|openapi' "$D_URLS/all-urls.txt" \
    | sort -u > "$D_URLS/interesting.txt" || true
  ok "urls: $(lines "$D_URLS/all-urls.txt") ($(lines "$D_URLS/params.txt") with params)"
}

# ------------------------------------------------------------ 4. JS assets --
extract_endpoints() { # extract_endpoints <file...>
  grep -hoaE 'https?://[A-Za-z0-9._~:/?#@!$&*+,;=%()-]+' "$@" 2>/dev/null
  grep -hoaE '/(api|v[0-9]+|graphql|rest|internal|admin|auth|oauth|user|account|upload|download|file|files|config|token)/[A-Za-z0-9._/?=&%:+-]*' "$@" 2>/dev/null
}

extract_secrets() { # extract_secrets <file...>
  grep -hoaE '(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|ghp_[0-9A-Za-z]{36}|xox[baprs]-[0-9A-Za-z-]{10,}|sk_live_[0-9A-Za-z]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})' "$@" 2>/dev/null
}

stage_js() {
  if [[ "$SKIP_JS" -eq 1 ]]; then warn "JS stage skipped"; return; fi
  if [[ ! -s "$D_URLS/all-urls.txt" ]]; then warn "js: no urls to inspect"; return; fi
  local final="$D_JS/js-urls.txt"
  if have "$final"; then log "js: reusing $(lines "$final") js urls"; else
    log "js: collecting javascript urls..."
    grep -E '\.js($|\?)|/js/' "$D_URLS/all-urls.txt" 2>/dev/null \
      | grep -viE '\.json($|\?)' | sort -u > "$final"
  fi

  if [[ "$FORCE" -eq 1 || -z "$(ls -A "$D_JS_FILES" 2>/dev/null)" ]]; then
    log "js: downloading $(lines "$final") files..."
    "$HTTPX" -l "$final" "${HDR_ARGS[@]}" \
      -silent -threads "$THREADS" -timeout 10 -mc 200 -srd "$D_JS_FILES" \
      >/dev/null 2>"$D_LOGS/js-download.err" || warn "js download had errors"
  fi

  local files=() search_dir="$D_JS_FILES/response"
  [[ -d "$search_dir" ]] || search_dir="$D_JS_FILES"
  while IFS= read -r -d '' f; do files+=("$f"); done \
    < <(find "$search_dir" -type f -size +0c ! -name index.txt -print0 2>/dev/null)

  if [[ "${#files[@]}" -gt 0 ]]; then
    log "js: extracting from ${#files[@]} files..."
    extract_endpoints "${files[@]}" | sed '/^$/d' | sort -u > "$D_JS/endpoints.txt"
    grep -E '^https?://' "$D_JS/endpoints.txt" | sort -u > "$D_JS/endpoints-absolute.txt" || true
    grep -E '^/' "$D_JS/endpoints.txt" | sort -u > "$D_JS/endpoints-relative.txt" || true
    extract_secrets "${files[@]}" | sort -u > "$D_JS/secrets.txt" || true
    ok "js: $(lines "$final") files, $(lines "$D_JS/endpoints.txt") endpoints, $(lines "$D_JS/secrets.txt") secret hits"
  else
    warn "js: no files downloaded"
  fi
}

# --------------------------------------------------------------- 5. nuclei --
stage_nuclei() {
  if [[ "$SKIP_NUCLEI" -eq 1 ]]; then warn "nuclei stage skipped"; return; fi
  local final="$D_NUCLEI/findings.jsonl"
  if have "$final"; then log "nuclei: reusing $(lines "$final") findings"; return; fi

  local targets="$D_HTTP/live-urls.txt"
  [[ "$NUCLEI_ON_URLS" -eq 1 ]] && targets="$D_URLS/all-urls.txt"
  if [[ ! -s "$targets" ]]; then warn "nuclei: no targets to scan"; return; fi
  if [[ -z "$(nuclei -tl 2>/dev/null | head -1)" ]]; then
    warn "nuclei: no templates installed; run 'nuclei -update-templates' and rerun"
    return
  fi
  log "nuclei: scanning $(lines "$targets") targets ($SEVERITY)..."
  local tmp="$final.tmp"
  nuclei -l "$targets" "${HDR_ARGS[@]}" \
    -severity "$SEVERITY" -silent -jsonl -c "$THREADS" -rl "$RATE_LIMIT" \
    -o "$tmp" >/dev/null || warn "nuclei exited non-zero"
  publish "$tmp" "$final"

  if [[ "$HAS_JQ" -eq 1 && -s "$final" ]]; then
    jq -r '[.templateID, (.info.severity // ""), .matched-at] | @tsv' "$final" \
      | sort -u > "$D_NUCLEI/findings.txt"
  fi
  ok "nuclei: $(lines "$final") findings"
}

# ------------------------------------------------------------------ summary --
summary() {
  local s="$D_META/summary-$RUN_TS.txt"
  {
    printf '%-28s %s\n' "target"            "$DOMAIN"
    printf '%-28s %s\n' "run id"            "$RUN_TS"
    printf '%-28s %s\n' "subdomains"        "$(lines "$D_SUBS/all-subs.txt")"
    printf '%-28s %s\n' "live hosts"        "$(lines "$D_HTTP/live-urls.txt")"
    printf '%-28s %s\n' "urls (katana)"     "$(lines "$D_URLS/katana.txt")"
    printf '%-28s %s\n' "urls (merged)"     "$(lines "$D_URLS/all-urls.txt")"
    printf '%-28s %s\n' "urls w/ params"    "$(lines "$D_URLS/params.txt")"
    printf '%-28s %s\n' "js urls"           "$(lines "$D_JS/js-urls.txt")"
    printf '%-28s %s\n' "js endpoints"      "$(lines "$D_JS/endpoints.txt")"
    printf '%-28s %s\n' "js secret hits"    "$(lines "$D_JS/secrets.txt")"
    printf '%-28s %s\n' "nuclei findings"   "$(lines "$D_NUCLEI/findings.jsonl")"
  } | tee "$s"

  echo "finished_utc=$(date -u +%FT%TZ)" >> "$D_META/run-$RUN_TS.env"
  echo
  ok "Done. Results: $OUT"
}

# --------------------------------------------------------------------- run --
stage_subs
stage_http
stage_urls
stage_js
stage_nuclei
summary
