#!/usr/bin/env bash
# bb-recon.sh — recon pipeline (the methodology, in the doc), in stages.
#
# NOT interactive and does NOT send traffic on its own until you ask: either run
# the whole thing with 'all', or pick a single stage. Each stage maps to a doc section.
#
# BEFORE running it, in EVERY session:
#     source ~/hunts/<prog>/env.sh      # exports WORK, PROGRAM, UA, YWH, ...
# then:
#     ~/hunts/bb-recon.sh all           # full pipeline, hands-off (normal use)
#     ~/hunts/bb-recon.sh <stage>       # a single stage (test/debug)
#
# Rate limit (requests/sec for httpx/ffuf/katana/dnsx): GENTLE default 5.
# Override at launch per scope:   RATE=15 ~/hunts/bb-recon.sh fuzz
#
# CLEAN output: only the [bb-recon] lines hit the screen (✓ results · ⚠ warnings).
# Tools' native banner/progress goes to $WORK/notes/tools.log (recoverable, not on screen).
#
# Uniform RESULT row — every stage that prints status+size+url uses the same format:
#     <icon>  STATUS      SIZE  URL   [-> redirect]
# so status and size always look the same across stages. Icons: 🟢/🟡/🔴 in summary,
# a neutral · elsewhere.
#
# Stages: all, check, enum, live, triage, catchall, quickhits, harvest, fuzz, summary, api, js, report.
#   all           orchestrator: runs ALL stages check→report in sequence, no prompts (normal use)
#   check         checks which tools are installed and which stages you can run (no traffic)
#   enum          subfinder + crt.sh over apex.txt → subs_all.txt → oos filter → subs_inscope.txt
#   live          dnsx (DNS pre-filter) + httpx → recon/live.txt   = the "live hosts" baseline
#   triage        STEP 1: 3 buckets from live.txt (ZERO traffic) → surface/browser_todo/discarded
#   catchall      STEP 2: 2 probes/host (TRAFFIC) → surface_ok / surface_catchall
#   quickhits     STEP 3: 7 sensitive paths on surface_ok (TRAFFIC) → quickhits.txt
#                          + size-variance filter (quickhits_interesting) + per-status 401/403-gated leads (quickhits_auth)
#   harvest       robots.txt + sitemap.xml host-mapped (little traffic) → robots_*/sitemap_urls.txt
#   fuzz          ffuf loop on surface_ok with a curated wordlist (REAL TRAFFIC) → content/ffuf_<host>.json
#   summary       readable digest of the ffuf output, by size-cluster (was ffuf-summary, now built in)
#   api           API/doc path loop on surface_ok, flags JSON-200 (TRAFFIC) → recon/api_json.txt
#   js            discovers+downloads .js bundles (katana if present, else naive crawl), manual triage → js/<host>/
#   report        reads every file above → one self-contained report.html (no traffic, additive)
#
# Always writes under the program folder ($WORK). Idempotent: safe to re-run.
set -euo pipefail

# absolute path to MYSELF, captured BEFORE the cd (needed by usage())
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

# ---------------------------------------------------------------- output helpers
# Only THESE lines reach the screen. Tools' native banner/progress (subfinder, httpx,
# ffuf, ...) goes to $TOOLLOG, not to the screen. Everything on stderr: stdout stays
# free for real data (pipes/files).
log()  { printf '\033[1;36m[bb-recon %s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }   # info
ok()   { printf '   \033[1;32m✓\033[0m %s\n' "$*" >&2; }                                 # result
warn() { printf '   \033[1;33m⚠\033[0m  %s\n' "$*" >&2; }                                 # warning
sub()  { printf '     \033[2m%s\033[0m\n' "$*" >&2; }                                     # detail
die()  { printf '\033[1;31m[bb-recon] ✗ %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }           # does the binary exist?
need() { have "$1" || die "missing '$1' in PATH. Install it or skip this stage."; }

# --- uniform RESULT row: <icon> STATUS SIZE  URL  [-> redirect] -----------------
# row <icon> <status> <size> <url> [redirect]
row() {
  local ic="$1" st="$2" sz="$3" url="$4" rd="${5:-}"
  local arrow=""; [ -n "$rd" ] && arrow="  -> $rd"
  printf '     %s %4s %9s  %s%s\n' "$ic" "$st" "$sz" "$url" "$arrow" >&2
}
# show_httpx <file>: pretty-print an httpx "url [status] [size]" file as uniform rows.
show_httpx() {
  awk '{ st=$2; sz=$3; gsub(/[][]/,"",st); gsub(/[][]/,"",sz);
         if (sz=="") sz="-";
         printf "     %s %4s %9s  %s\n", "\xc2\xb7", st, sz, $1 }' "$1" >&2
}
# esc <string>: HTML-escape a shell value (& < >) for the report.
esc() { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

# ---------------------------------------------------------------- env guards
# 'check' and help do NOT need a program: let them run without $WORK.
case "${1:-}" in check|-h|--help|help|"") SKIP_ENV=1 ;; esac

# The script runs in a subshell: variables MUST come from 'source env.sh'.
if [ -z "${SKIP_ENV:-}" ]; then
  [ -n "${WORK:-}" ]  || die "\$WORK not set. First run:  source ~/hunts/<prog>/env.sh"
  [ -d "$WORK" ]      || die "\$WORK ($WORK) is not a directory. Did you run bb-init.sh?"
  cd "$WORK"
  mkdir -p recon content js notes
fi

# path defaults if env.sh is old and doesn't export them all.
# ${WORK:-}: in check/help mode $WORK is unset (set -u) and these paths aren't needed anyway.
: "${SUBS:=${WORK:-}/recon/subs_all.txt}"
: "${INSCOPE:=${WORK:-}/recon/subs_inscope.txt}"
: "${APEX_FILE:=${WORK:-}/recon/apex.txt}"
: "${OOS_FILE:=${WORK:-}/recon/oos.txt}"
: "${UA:=Mozilla/5.0}"
: "${YWH:=}"
# rate limit (requests/sec) for the tools that hit the TARGET (httpx/ffuf/katana). GENTLE default 5.
# Override at launch per scope:  RATE=15 ~/hunts/bb-recon.sh fuzz
: "${RATE:=5}"
# DNS resolution (dnsx) goes to PUBLIC resolvers (1.1.1.1/8.8.8.8/9.9.9.9), NOT the target,
# so it can be much faster safely. Decoupled from RATE: on big scopes this is the difference
# between minutes and hours. Lower it if your own network/resolver complains.
: "${DNS_RATE:=100}"
# dnsx concurrency. On big lists the real bottleneck isn't the rate but how many lookups
# run at once: dead hosts sit in timeout and tie up a thread. Still, too many concurrent
# lookups saturate a home router's NAT/conntrack table and stall the whole line — so 40
# is the safe default for a consumer connection. Raise it (60/80) only on a robust link.
: "${DNS_THREADS:=40}"
# DNS resolvers used by dnsx/httpx. Default = public (1.1.1.1/8.8.8.8/9.9.9.9), NOT the target.
# On a home line behind a firewall (pfSense/OPNsense), firing tens of thousands of UDP/53 flows
# straight at public resolvers can saturate the state table and queries start getting dropped —
# the scan "starts fast then stalls". Fix: point this at your LOCAL resolver (the gateway's
# Unbound), which caches, dedups and talks upstream as one well-behaved client:
#     DNS_RESOLVERS=192.168.1.1 ~/hunts/bb-recon.sh live
: "${DNS_RESOLVERS:=1.1.1.1,8.8.8.8,9.9.9.9}"
# Chunked resolve. Some gateways (home firewalls, NAT on virtualized setups) cap the number of
# tracked connections and simply wedge once it fills — the resolve "starts fast then stalls
# at ~the same number every time". Instead of one giant dnsx run that piles up states, we
# resolve DNS_CHUNK hosts, pause DNS_PAUSE seconds so the state table drains, then continue.
# DNS_CHUNK=0 disables chunking (one single run, the old behaviour).
: "${DNS_CHUNK:=3000}"
: "${DNS_PAUSE:=20}"
# Resume: when you re-run a stage that was INTERRUPTED (Ctrl+C) mid-loop, skip the hosts already
# done instead of redoing them. A stage that completed normally still re-runs fresh (deliberate
# re-run = fresh results). Currently wired on the two long per-host loops: fuzz and api. RESUME=0 off.
: "${RESUME:=1}"

# where tools' native output (banner/progress/warnings) goes: to a file, not the screen.
# The screen stays clean with just the [bb-recon] lines; if a tool looks silent, look here.
: "${TOOLLOG:=${WORK:-}/notes/tools.log}"

# headers for curl/httpx: YWH only if set (some programs don't want it)
HDRS=(-H "User-Agent: $UA")
# YWH is an extra identification header, but ONLY if it's a real "Name: value" (has a colon).
# A value without a colon (e.g. a '-BugBounty-xxx' UA-suffix mistakenly put here) would be
# passed as '-H -BugBounty-xxx' → httpx/curl parse the leading '-' as a flag and break silently.
if [ -n "$YWH" ]; then
  case "$YWH" in
    *:*) HDRS+=(-H "$YWH") ;;
    *)   warn "ignoring malformed identification '$YWH' (not a 'Name: value' header). Put that string in the UA instead (bb-init option 1)." ;;
  esac
fi

# kestrel: every extra custom header from the program's headers.txt (one "Name: value" per line)
if [ -n "${HEADERS_FILE:-}" ] && [ -s "$HEADERS_FILE" ]; then
  while IFS= read -r _h || [ -n "$_h" ]; do
    case "$_h" in *:*) [ "$_h" = "$YWH" ] || HDRS+=(-H "$_h") ;; esac
  done < "$HEADERS_FILE"
fi
# timeout for EVERY curl in the loops: a hanging host (WAF dropping us) won't block everything
CT=(--connect-timeout 5 --max-time 12)

# PROXY (set only when a kestrel command exports it): route TARGET traffic through an
# intercepting proxy (Burp / Caido) so every request kestrel makes lands in its history/sitemap.
# Deliberately scoped: only the invocations that hit the target are proxied. Non-target traffic
# (crt.sh, subfinder's sources, DNS) stays direct, so the proxy never fills with OSINT noise.
PX_HTTPX=(); PX_FFUF=(); PX_CURL=()
if [ -n "${PROXY:-}" ]; then
  PX_HTTPX=(-proxy "$PROXY")   # httpx and katana both take -proxy
  PX_FFUF=(-x "$PROXY")
  PX_CURL=(-x "$PROXY")
  log "proxy: routing target traffic through $PROXY"
fi
# tcurl: a curl that honours the proxy for TARGET requests. Plain 'curl' stays direct (crt.sh).
tcurl() { curl ${PX_CURL[@]+"${PX_CURL[@]}"} "$@"; }

# proxy liveness: the command layer preflights the proxy before we start, but it can die MID-RUN.
# These let run_stage re-check it between stages so we stop instead of probing blind into a dead
# proxy (every request would fail silently and the stage would write empty results).
proxy_alive() {   # true if $PROXY's TCP port is accepting connections
  local hp="${PROXY#*://}"; hp="${hp%%/*}"
  local host="${hp%%:*}" port="${hp##*:}"
  [ "$host" = "$port" ] && port=8080
  [ -n "$host" ] || host=127.0.0.1
  if have timeout; then timeout 2 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
  else (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; fi
}
# stages that send traffic to the TARGET — these need the proxy up when --proxy is on
_proxied_stage() { case "$1" in live|catchall|quickhits|harvest|fuzz|api|js) return 0 ;; *) return 1 ;; esac; }
# proxy_guard <stage>: stop clean if --proxy is on, this stage hits the target, and the proxy went
# down. Called both per-stage in the full pipeline and once at the single-stage dispatcher, so
# `kestrel recon` (which runs one stage per engine call) is covered too.
proxy_guard() {
  [ -n "${PROXY:-}" ] || return 0
  _proxied_stage "$1" || return 0
  proxy_alive && return 0
  printf '\n   \033[1;31m✗\033[0m  proxy %s went down — stopping before '\''%s'\'' instead of probing blind.\n' "$PROXY" "$1" >&2
  printf '      reopen Burp/Caido and re-run, or replay what you already have:  kestrel replay <program> --proxy\n' >&2
  exit 3
}

# CASE A (fixed host list) vs CASE B (wildcard): is there a non-empty apex.txt?
# NB: the MIXED scenario (wildcard + standalone hosts) will be handled by a unified
#     scope.txt model — to be done together with bb-init (deferred).
is_wildcard() { [ -s "$APEX_FILE" ]; }

# ---------------------------------------------------------------- check (tool preflight)
# Checks which binaries are installed and which stages you can run. No traffic, no $WORK.
stage_check() {
  log "Checking tools on the system (✓ present · ✗ missing):"
  local t name role lvl m miss=0
  # "name|what it's for|level"
  for t in \
    "curl|HTTP, used by almost every stage|core" \
    "httpx|live, quickhits, harvest|core" \
    "jq|summary / report (JSON parsing)|core" \
    "subfinder|enum (wildcard scope)|stage" \
    "ffuf|fuzz|stage" \
    "dnsx|live: DNS pre-filter (optional, recommended)|opt" \
    "katana|js: crawl with JS execution (else curl fallback)|opt" \
    "trufflehog|offline secret triage on js/ (optional)|opt" ; do
    name=${t%%|*}; role=${t#*|}; role=${role%|*}; lvl=${t##*|}
    if have "$name"; then m="✓"; else m="✗"; [ "$lvl" = core ] && miss=$((miss+1)); fi
    printf '   %s  %-11s %-48s [%s]\n' "$m" "$name" "$role" "$lvl" >&2
  done
  echo >&2
  if [ "$miss" -eq 0 ]; then
    ok "CORE complete (curl, httpx, jq): the base pipeline + digests run."
  else
    warn "$miss CORE tool(s) missing: install them before proceeding."
  fi
}

# ----------------------------------------------------------------  enum
stage_enum() {
  # No wildcard apex → nothing to enumerate (hosts-only scope). Skip cleanly so 'all'
  # doesn't abort: the standalone hosts go straight into 'live' via recon/hosts.txt.
  is_wildcard || { warn "no wildcard apex (apex.txt empty): skipping enum — hosts-only scope goes straight to 'live'."; return 0; }
  need subfinder
  log "enum over $(wc -l < "$APEX_FILE") apex from $APEX_FILE"
  while read -r d; do
    [ -z "$d" ] && continue
    subfinder -d "$d" -silent 2>>"$TOOLLOG" || true
    curl -s "${HDRS[@]}" "https://crt.sh/?q=%25.$d&output=json" \
      | grep -oE "[a-zA-Z0-9._-]+\.$d" || true
  done < "$APEX_FILE" | sed -E 's/^[*.]+//' | sort -u > "$SUBS"
  ok "subs=$(wc -l < "$SUBS") → $SUBS"

  # out-of-scope filter: empty/missing oos.txt → pass everything
  if [ -s "$OOS_FILE" ]; then
    grep -vFf "$OOS_FILE" "$SUBS" > "$INSCOPE"
    ok "inscope=$(wc -l < "$INSCOPE") → $INSCOPE"
  else
    cp "$SUBS" "$INSCOPE"
    ok "inscope=$(wc -l < "$INSCOPE") → $INSCOPE"
  fi
}

# ----------------------------------------------------------------  live
stage_live() {
  # UNIFIED/MIXED scope: the probe list is the UNION of
  #   (a) enumerated in-scope subs ($INSCOPE), present when the scope has wildcard apex, and
  #   (b) standalone hosts (arg, else recon/hosts.txt), present when the scope lists exact hosts.
  # A program with BOTH wildcards and standalone hosts works in one go.
  local src="recon/_probe_input.txt"; : > "$src"; local had=0
  if is_wildcard; then
    if [ -s "$INSCOPE" ]; then cat "$INSCOPE" >> "$src"; had=1
    else warn "wildcard apex present but $INSCOPE empty: run 'enum' first (skipping its subs for now)."; fi
  fi
  local hostsrc="${1:-recon/hosts.txt}"
  if [ -s "$hostsrc" ]; then cat "$hostsrc" >> "$src"; had=1
  elif [ -n "${TARGET:-}" ] && [ "$had" -eq 0 ]; then printf '%s\n' "$TARGET" >> "$src"; had=1
    log "single-target fallback: using \$TARGET ($TARGET)"
  fi
  [ "$had" -eq 1 ] || die "no input hosts. Add wildcard apex to scope (then 'enum'), or put hosts in recon/hosts.txt."
  sort -u "$src" -o "$src"
  log "live input: $(wc -l < "$src") hosts (enum subs ∪ standalone hosts)"

  # DNS pre-filter (optional): keep only what resolves → httpx wastes no timeouts
  if have dnsx; then
    local total; total=$(wc -l < "$src")
    : > recon/resolved.txt
    if [ "$DNS_CHUNK" -gt 0 ] && [ "$total" -gt "$DNS_CHUNK" ]; then
      # chunked: resolve DNS_CHUNK at a time, pause between so the NAT/state table drains.
      log "dnsx: chunked resolve of $total hosts (rl $DNS_RATE, chunk $DNS_CHUNK)"
      local part="recon/_dns_chunk.txt" i=0 done=0
      split -l "$DNS_CHUNK" -d "$src" recon/_dns_part_
      for part in recon/_dns_part_*; do
        i=$((i+1)); done=$((done+$(wc -l < "$part")))
        dnsx -l "$part" -r "$DNS_RESOLVERS" -rl "$DNS_RATE" -t "$DNS_THREADS" -silent >> recon/resolved.txt 2>>"$TOOLLOG" || true
        printf '\r   resolve %d/%d · ok %d' "$done" "$total" "$(wc -l < recon/resolved.txt)" >&2
        [ "$done" -lt "$total" ] && sleep "$DNS_PAUSE"
      done
      printf '\r%-60s\r' '' >&2
      rm -f recon/_dns_part_*
    else
      log "dnsx: DNS pre-filter over $total hosts (rl $DNS_RATE)"
      dnsx -l "$src" -r "$DNS_RESOLVERS" -rl "$DNS_RATE" -t "$DNS_THREADS" -silent > recon/resolved.txt 2>>"$TOOLLOG" || true
    fi
    sort -u recon/resolved.txt -o recon/resolved.txt
    ok "resolved=$(wc -l < recon/resolved.txt) → recon/resolved.txt"
    src="recon/resolved.txt"
  else
    warn "dnsx missing: skipping the DNS pre-filter (recommended on large lists)"
  fi
  [ -s "$src" ] || die "no hosts to probe in $src."

  need httpx
  log "httpx: live-host triage over $(wc -l < "$src") hosts (rl $RATE, timeout 5)"
  httpx -l "$src" "${HDRS[@]}" ${PX_HTTPX[@]+"${PX_HTTPX[@]}"} \
    -sc -title -td -server -cl -location \
    -r "$DNS_RESOLVERS" \
    -t 50 -timeout 5 -retries 1 -rl "$RATE" -stats \
    -o recon/live.txt >>"$TOOLLOG" 2>&1 || true
  touch recon/live.txt
  local nlive; nlive=$(wc -l < recon/live.txt)
  if [ "$nlive" -eq 0 ]; then
    warn "0 live hosts from a non-empty input — this is almost always a TOOL error, not a real result."
    warn "Check $TOOLLOG (bad flag? malformed -H header?). Fix and re-run 'live'."
  else
    ok "live=$nlive → recon/live.txt"
  fi
}

# ----------------------------------------------------------------  STEP 1 triage (0 traffic)
stage_triage() {
  [ -s recon/live.txt ] || die "missing recon/live.txt: run 'live' first."
  : > recon/discarded.txt; : > recon/browser_todo.txt; : > recon/surface.txt; : > recon/rescued.txt

  # Single-pass awk partition (no IGNORECASE: mawk, the default awk on Debian/Ubuntu, lacks it).
  #   HARD   = really dead (000/522/istio/SSO): NEVER rescued.
  #   CFWALL = Cloudflare bot-block wall: tools blocked, a browser gets through → browser_todo.
  #   404    = empty root, BUT if the host "speaks" (API/auth name) or has a recognizable
  #            infra server banner → not dead, has surface on paths → RESCUE into surface.
  #   rest   = 200/401/403-body/405/5xx/3xx → surface.
  # NAME: infra token in the hostname ($1). SERV: server/tech banner (fixed case) in the line.
  awk '
    BEGIN{
      NAME="(^|[.-])(api|apis|sts|idp|token|auth|oauth|sso|gateway|gw|graphql|rest|admin)([.-]|$)"
      SERV="Azure-Application-Gateway|Microsoft-HTTPAPI|AmazonS3|Amazon CloudFront|CloudFront|Kong|Kestrel|Microsoft-IIS|openresty|gunicorn|Express"
    }
    {
      hard = ($0 ~ /\[000\] |\[522\] |\[403\] \[\] \[19\]|accounts\.google\.com/)
      cf   = ($0 ~ /Attention Required|Cloudflare Bot Management|Just a moment/)
      nf   = ($0 ~ /\[404\] /)
      # hostname = part after // up to the first /
      h=$1; sub(/^https?:\/\//,"",h); sub(/\/.*/,"",h)
      if (hard) { print            > "recon/discarded.txt"; next }
      if (cf)   { print $1          > "recon/browser_todo.txt"; next }
      if (nf) {
        if (h ~ NAME || $0 ~ SERV) { print $1 > "recon/surface.txt"; print $0 > "recon/rescued.txt" }
        else                       { print $0 > "recon/discarded.txt" }
        next
      }
      print $1 > "recon/surface.txt"
    }' recon/live.txt

  sort -u -o recon/surface.txt       recon/surface.txt
  sort -u -o recon/browser_todo.txt  recon/browser_todo.txt

  ok "surface=$(wc -l < recon/surface.txt)  browser_todo=$(wc -l < recon/browser_todo.txt)  discarded=$(wc -l < recon/discarded.txt)"
  if [ -s recon/rescued.txt ]; then ok "rescued=$(wc -l < recon/rescued.txt) → recon/rescued.txt"; fi
}

# ----------------------------------------------------------------  STEP 2 catchall (traffic)
stage_catchall() {
  [ -s recon/surface.txt ] || die "missing recon/surface.txt: run 'triage' first."
  local n; n=$(wc -l < recon/surface.txt)
  log "catch-all: $n hosts, ~$((n*2)) requests"
  : > recon/surface_ok.txt; : > recon/surface_catchall.txt   # reset: no accumulation across runs
  local i=0
  while read -r u; do
    [ -z "$u" ] && continue
    i=$((i+1)); printf '\r   [%d/%d] %-50.50s' "$i" "$n" "$u" >&2
    c1=$(tcurl -s -o /dev/null -w '%{http_code}' "${HDRS[@]}" "$u/zzznope$RANDOM" || echo 000)
    c2=$(tcurl -s -o /dev/null -w '%{http_code}' "${HDRS[@]}" "$u/zzzxxx$RANDOM" || echo 000)
    if [ "$c1" = "200" ] && [ "$c2" = "200" ]; then echo "$u" >> recon/surface_catchall.txt
    else                                            echo "$u" >> recon/surface_ok.txt; fi
  done < recon/surface.txt
  printf '\r%-70s\r' '' >&2
  ok "surface_ok=$(wc -l < recon/surface_ok.txt)  surface_catchall=$(wc -l < recon/surface_catchall.txt)"
}

# ----------------------------------------------------------------  STEP 3 quickhits (traffic)
stage_quickhits() {
  [ -s recon/surface_ok.txt ] || die "missing recon/surface_ok.txt: run 'catchall' first."
  need httpx
  local n; n=$(wc -l < recon/surface_ok.txt)
  # 7 "key" paths: the same quick-hits as the doc. NB not on catch-alls (every path → 200 = noise).
  local PATHS="/.git/config,/.env,/api,/swagger-ui.html,/v3/api-docs,/wp-json/,/actuator/env"
  log "quick-hits: $n hosts, ~$((n*7)) requests"
  httpx -l recon/surface_ok.txt \
    -path "$PATHS" "${HDRS[@]}" ${PX_HTTPX[@]+"${PX_HTTPX[@]}"} \
    -sc -cl -mc 200,401,403,500 \
    -t 20 -rl "$RATE" -silent \
    -o recon/quickhits.txt >>"$TOOLLOG" 2>&1
  ok "quickhits=$(wc -l < recon/quickhits.txt) → recon/quickhits.txt"

  # False-positive filter: keep only hosts where SIZE VARIES across paths
  # (all equal = index/residual catch-all = noise; one odd size = a file that stands out).
  awk '
    $2=="[]"||$2=="" { next }                 # drop empty/broken responses
    {
      sz=$3; gsub(/[][]/,"",sz);
      split($1,a,"/"); host=a[1]"//"a[3];      # scheme://host (mawk: no backref, use split)
      buf[host]=buf[host] $0 ORS;
      if(!(host in first)) first[host]=sz;
      if(sz!=first[host]) varies[host]=1;
    }
    END{ for(h in buf) if(h in varies) printf "%s", buf[h] }' recon/quickhits.txt \
    > recon/quickhits_interesting.txt

  if [ -s recon/quickhits_interesting.txt ]; then
    log "hosts with an ODD size → recon/quickhits_interesting.txt:"
    show_httpx recon/quickhits_interesting.txt
  else
    log "no host with an odd size."
  fi

  # Per-status signal: leads the size filter MISSES (uniform body).
  #   401            = the API exists and asks for auth → always interesting.
  #   403 with body>0 on a host that "speaks" (api/auth/…) = gated API → bypass? (one line per host)
  # File format: uniform "url [status] [size]" rows (401) + "403-gated <host>" flags.
  awk '
    BEGIN{ NAME="(api|apis|sts|idp|token|auth|oauth|sso|gateway|gw|graphql|rest|admin)" }
    $2=="[401]" { print $0; next }
    $2=="[403]" && $3!="[0]" && $3!="[]" {
      h=$1; sub(/^https?:\/\//,"",h); sub(/\/.*/,"",h)
      if (h ~ NAME && !(h in seen)) { seen[h]=1; print "403-gated " h }
    }' recon/quickhits.txt > recon/quickhits_auth.txt

  if [ -s recon/quickhits_auth.txt ]; then
    log "per-STATUS leads (401 · 403-gated) → recon/quickhits_auth.txt:"
    # one awk handles both line shapes: "403-gated <host>" flags and "url [status] [size]" rows
    awk '/^403-gated /{ printf "     %s 403-gated  %s\n","\xc2\xb7",$2; next }
         { st=$2; sz=$3; gsub(/[][]/,"",st); gsub(/[][]/,"",sz); if(sz=="")sz="-";
           printf "     %s %4s %9s  %s\n","\xc2\xb7",st,sz,$1 }' recon/quickhits_auth.txt >&2
  else
    log "no 401 and no recognizable gated API."
  fi
}

# ---------------------------------------------------------------- OOS paths (excluded on every host)
# recon/oos_paths.txt holds literal path prefixes the program excludes on ALL hosts (e.g. /arcgis/).
# _oos_regex emits an ERE alternation of the escaped prefixes (empty if none defined);
# _oos_filter drops stdin lines whose URL/path contains one (plain passthrough when none defined).
_oos_regex() {
  [ -s recon/oos_paths.txt ] || return 0
  sed -e 's/[][(){}.^$*+?|\\]/\\&/g' recon/oos_paths.txt | awk 'NF' | paste -sd'|' -
}
_oos_filter() {
  local re; re="$(_oos_regex)"
  if [ -n "$re" ]; then grep -ivE "$re"; else cat; fi
}

# ----------------------------------------------------------------  harvest robots+sitemap (little traffic)
stage_harvest() {
  [ -s recon/surface.txt ] || die "missing recon/surface.txt: run 'triage' first."
  need httpx

  # a) hosts with a REAL robots.txt (-ms Disallow drops catch-all index pages)
  log "robots: looking for real robots.txt over $(wc -l < recon/surface.txt) hosts"
  httpx -l recon/surface.txt -path /robots.txt "${HDRS[@]}" ${PX_HTTPX[@]+"${PX_HTTPX[@]}"} \
    -mc 200 -ms "Disallow" -r "$DNS_RESOLVERS" \
    -t 50 -timeout 5 -rl "$RATE" -silent -o recon/robots_urls.txt >>"$TOOLLOG" 2>&1 || true
  sort -u recon/robots_urls.txt -o recon/robots_urls.txt 2>/dev/null || : > recon/robots_urls.txt
  ok "robots=$(wc -l < recon/robots_urls.txt) → recon/robots_urls.txt"

  # b) extract directives KEEPING the host (base prefix before the global sort)
  : > recon/robots_paths.txt
  while read -r u; do
    [ -z "$u" ] && continue
    base="${u%/robots.txt}"
    tcurl -s "${CT[@]}" "${HDRS[@]}" "$u" | tr -d '\r' \
      | grep -iE '^(dis)?allow:|^sitemap:' \
      | sed -E "s#^#${base}  ->  #" || true
  done < recon/robots_urls.txt | sort -u > recon/robots_paths.txt
  if [ -s recon/oos_paths.txt ]; then
    _oos_filter < recon/robots_paths.txt > recon/robots_paths.tmp && mv recon/robots_paths.tmp recon/robots_paths.txt
  fi
  ok "robots_paths=$(wc -l < recon/robots_paths.txt) → recon/robots_paths.txt"

  # c) full URLs of the Disallow/Allow → direct check (you already know them, don't fuzz)
  : > recon/robots_targets.txt
  while read -r u; do
    [ -z "$u" ] && continue
    base="${u%/robots.txt}"
    tcurl -s "${CT[@]}" "${HDRS[@]}" "$u" | tr -d '\r' \
      | grep -iE '^(dis)?allow:[[:space:]]*/' \
      | sed -E 's/^[^:]+:[[:space:]]*//; s/\$$//; s/\*.*$//' \
      | awk 'NF && $0!="/"' \
      | sed -E "s#^#${base}#" || true
  done < recon/robots_urls.txt | sort -u > recon/robots_targets.txt
  if [ -s recon/oos_paths.txt ]; then
    _oos_filter < recon/robots_targets.txt > recon/robots_targets.tmp && mv recon/robots_targets.tmp recon/robots_targets.txt
    ok "oos-paths: out-of-scope paths dropped → robots_targets not curled on them"
  fi
  ok "robots_targets=$(wc -l < recon/robots_targets.txt) → recon/robots_targets.txt"
  if [ -s recon/robots_targets.txt ]; then
    # direct check: status+size per target, saved to a file (was screen-only). Screen shows
    # only a progress counter; the rows live in recon/robots_checked.txt for the report/review.
    local nt i=0; nt=$(wc -l < recon/robots_targets.txt)
    : > recon/robots_checked.txt
    while read -r t; do
      [ -z "$t" ] && continue
      i=$((i+1)); printf '\r   [%d/%d] %-50.50s' "$i" "$nt" "$t" >&2
      # command substitution (not 'read < <(...)'): curl's -w has no trailing newline,
      # and a newline-less 'read' returns non-zero → under set -e it would abort the stage.
      resp=$(tcurl -s -o /dev/null -w '%{http_code} %{size_download}' "${CT[@]}" "${HDRS[@]}" "$t" 2>/dev/null || echo "000 0")
      printf '%s %s %s\n' "${resp%% *}" "${resp##* }" "$t" >> recon/robots_checked.txt
    done < recon/robots_targets.txt
    printf '\r%-70s\r' '' >&2
    ok "robots_checked=$(wc -l < recon/robots_checked.txt) → recon/robots_checked.txt"
  fi

  # d) sitemap.xml = the gold (real URLs). 1 level of recursion on index files
  { grep -i '^.*Sitemap:' recon/robots_paths.txt 2>/dev/null | sed -E 's/.*Sitemap:[[:space:]]*//I' || true; \
    sed 's#$#/sitemap.xml#' recon/surface_ok.txt 2>/dev/null || true; } | sort -u > recon/sitemaps.txt
  : > recon/sitemap_urls.txt
  while read -r s; do
    [ -z "$s" ] && continue
    locs=$(tcurl -s "${CT[@]}" "${HDRS[@]}" "$s" | grep -oE '<loc>[^<]+' | sed 's/<loc>//') || true
    if echo "$locs" | grep -qE '\.xml($|\?)'; then      # sitemapindex → go one level down
      echo "$locs" | grep -E '\.xml($|\?)' | while read -r c; do
        tcurl -s "${CT[@]}" "${HDRS[@]}" "$c" | grep -oE '<loc>[^<]+' | sed 's/<loc>//' || true
      done
    else
      echo "$locs"
    fi
  done < recon/sitemaps.txt | sort -u > recon/sitemap_urls.txt
  if [ -s recon/oos_paths.txt ]; then
    _oos_filter < recon/sitemap_urls.txt > recon/sitemap_urls.tmp && mv recon/sitemap_urls.tmp recon/sitemap_urls.txt
  fi
  ok "sitemap_urls=$(wc -l < recon/sitemap_urls.txt) → recon/sitemap_urls.txt"
  warn "scope: robots/sitemap can reveal third-party/staging hosts → check the brief, often out of scope."
}

# ----------------------------------------------------------------  fuzz (REAL TRAFFIC: ffuf loop)
stage_fuzz() {
  [ -s recon/surface_ok.txt ] || die "missing recon/surface_ok.txt: run 'catchall' first."
  need ffuf
  # CURATED wordlist (~80 paths), NOT the 30k raft lists: the host×words multiplier is lethal.
  local CURATED="${CURATED:-$HOME/hunts/wordlists/curated.txt}"
  [ -s "$CURATED" ] || die "missing curated wordlist: $CURATED. Put it there or export CURATED=/path/to/list."

  # Zero duplicates across the whole pipeline: curated MINUS quick-hits ( S3) MINUS robots ().
  printf '%s\n' .git/config .env api swagger-ui.html v3/api-docs wp-json actuator/env > recon/quickhits_tokens.txt
  if [ -s recon/robots_paths.txt ]; then
    grep -iE 'allow:' recon/robots_paths.txt \
      | sed -E 's/^.*(dis)?allow:[[:space:]]*//I; s/\r$//; s/\?.*$//; s/\*.*$//; s#^/+##; s#/+$##' \
      | awk 'NF' | sort -u > recon/robots_tokens.txt
  else
    : > recon/robots_tokens.txt
    warn "no recon/robots_paths.txt (harvest not run) → not subtracting robots tokens."
  fi
  grep -vxFf recon/quickhits_tokens.txt "$CURATED" \
    | grep -vxFf recon/robots_tokens.txt - \
    | sort -u > recon/wl_trimmed.txt
  # drop wordlist tokens that are themselves a single-segment out-of-scope dir (e.g. /admin/ → admin),
  # so fuzz never requests a top-level OOS path. Multi-segment OOS paths are left to the crawl/filter.
  if [ -s recon/oos_paths.txt ]; then
    sed 's#^/\+##; s#/\+$##' recon/oos_paths.txt | awk -F/ 'NF==1 && $1!=""' | sort -u > recon/oos_path_tokens.txt
    if [ -s recon/oos_path_tokens.txt ]; then
      grep -vxiFf recon/oos_path_tokens.txt recon/wl_trimmed.txt > recon/wl_trimmed.tmp && mv recon/wl_trimmed.tmp recon/wl_trimmed.txt
    fi
  fi

  local n w; n=$(wc -l < recon/surface_ok.txt); w=$(wc -l < recon/wl_trimmed.txt)
  log "fuzz loop: $w paths × $n hosts, ~$((w*n)) requests"
  mkdir -p content
  # RESUME: if the previous fuzz was interrupted (flag still present), skip hosts whose
  # ffuf_<host>.json is already a complete, valid JSON. A normal completed run clears the flag,
  # so a later deliberate re-run starts fresh (re-fuzzes every host).
  local FLAG="recon/.fuzz_inprogress" RESUMING=0 i=0
  if [ -f "$FLAG" ] && [ "$RESUME" = 1 ]; then RESUMING=1; log "resume: skipping hosts already done"; fi
  touch "$FLAG"
  while read -r u; do
    [ -z "$u" ] && continue
    i=$((i+1)); printf '\r   [%d/%d] %-50.50s' "$i" "$n" "$u" >&2
    host=$(echo "$u" | sed -E 's#https?://##; s#/.*##')
    if [ "$RESUMING" = 1 ] && [ -s "content/ffuf_${host}.json" ] && jq -e . "content/ffuf_${host}.json" >/dev/null 2>&1; then
      continue
    fi
    ffuf -u "$u/FUZZ" -w recon/wl_trimmed.txt \
      "${HDRS[@]}" ${PX_FFUF[@]+"${PX_FFUF[@]}"} \
      -ac -mc 200,301,302,401,403,500 \
      -t 20 -rate "$RATE" -p 0.1 -maxtime-job 180 -s \
      -o "content/ffuf_${host}.json" -of json >>"$TOOLLOG" 2>&1 || true
  done < recon/surface_ok.txt
  printf '\r%-70s\r' '' >&2
  rm -f "$FLAG"
  ok "fuzz done → content/*.json (digest in report.html / summary)"
}

# ----------------------------------------------------------------  api enum loop (TRAFFIC)
# GENERIC part (fixed set of API/doc paths) on surface_ok. Flags whoever returns REAL JSON (200),
# not the HTML shell. CMS-specific parts (wp-json namespaces, Drupal jsonapi) are NOT looped
# wholesale: do them by hand on the hosts the fingerprint () marks as that CMS.
stage_api() {
  [ -s recon/surface_ok.txt ] || die "missing recon/surface_ok.txt: run 'catchall' first."
  local APIP="/api /api/v1 /rest /graphql /swagger-ui.html /v2/api-docs /v3/api-docs /openapi.json /.well-known/openid-configuration /actuator /actuator/env /health /actuator/health /info /metrics"
  local n np; n=$(wc -l < recon/surface_ok.txt); np=$(echo $APIP | wc -w)
  log "api enum loop: $np paths × $n hosts, ~$((np*n)) requests"
  # RESUME: a persistent RAW accumulator + a done-list of hosts. If the previous api run was
  # interrupted (flag present), skip hosts already done and keep their accumulated results; the
  # final api_json.txt is built from the FULL RAW so the signature clustering stays correct.
  local body FLAG RAW DONE RESUMING=0
  FLAG="recon/.api_inprogress"; RAW="recon/.api_raw.txt"; DONE="recon/.api_done.txt"; body=$(mktemp)
  local -A _done=()
  if [ -f "$FLAG" ] && [ "$RESUME" = 1 ] && [ -f "$RAW" ]; then
    RESUMING=1
    [ -f "$DONE" ] && while IFS= read -r _h; do _done["$_h"]=1; done < "$DONE"
    log "resume: continuing the interrupted api loop (${#_done[@]} hosts already done)."
  else
    : > "$RAW"; : > "$DONE"
  fi
  touch "$FLAG"
  local i=0
  while read -r u; do
    [ -z "$u" ] && continue
    i=$((i+1)); printf '\r   [%d/%d] %-50.50s' "$i" "$n" "$u" >&2
    if [ "$RESUMING" = 1 ] && [ -n "${_done[$u]:-}" ]; then continue; fi
    for p in $APIP; do
      resp=$(tcurl -s "${CT[@]}" -o "$body" -w '%{http_code} %{size_download} %{content_type}' "${HDRS[@]}" "$u$p" || echo "000 0 -")
      code=${resp%% *}; rest=${resp#* }; size=${rest%% *}; ct=${rest#* }
      case "$ct" in *json*) : ;; *) continue ;; esac
      [ "$code" = "200" ] || continue
      # Structural signature: lowercase, drop hex ids / digits / whitespace, then checksum.
      # Identical error envelopes (timestamps, traceids, requestId differ) collapse to ONE sig,
      # so the same gateway error across N hosts is counted as one cluster, not N leads.
      local low sig known snip
      low=$(head -c 1024 "$body" | tr 'A-Z' 'a-z')
      sig=$(printf '%s' "$low" | tr -d ' \t\r\n' | sed -E 's/[0-9a-f]{8,}//g; s/[0-9]+//g' | cksum | cut -d' ' -f1)
      known=0
      case "$low" in
        *referercheckfailed*|*no_interface_def*|*'"resultstatus":"f"'*|*'"stat":"fail"'*|*'"success":false'*|*accessdenied*|*'access denied'*|*unauthorized*) known=1 ;;
      esac
      snip=$(head -c 120 "$body" | tr '\n\t' '  ' | sed 's/  */ /g')
      printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$code" "$size" "$sig" "$known" "$u$p" "$snip" >> "$RAW"
    done
    printf '%s\n' "$u" >> "$DONE"
  done < recon/surface_ok.txt
  printf '\r%-70s\r' '' >&2
  rm -f "$body"

  : > recon/api_json.txt; : > recon/api_json_noise.txt
  if [ -s "$RAW" ]; then
    # A signature shared by >=3 URLs = gateway/catch-all error = noise. Known error envelopes
    # go straight to noise. Everything else = a REAL JSON 200 worth opening.
    awk -F'\t' '
      { cnt[$3]++; rows[NR]=$0 }
      END{
        for(i=1;i<=NR;i++){
          split(rows[i],f,"\t"); code=f[1]; size=f[2]; sig=f[3]; known=f[4]; url=f[5]; snip=f[6];
          if(known=="1" || cnt[sig]>=3) print code"\t"size"\t"url"\t"snip"\t(x"cnt[sig]")" >> "recon/api_json_noise.txt";
          else                          print code" "size" "url >> "recon/api_json.txt";
        }
      }' "$RAW"
  fi
  rm -f "$RAW" "$DONE" "$FLAG"

  if [ -s recon/api_json.txt ]; then
    log "REAL JSON 200 (body is NOT a known gateway/error envelope) → recon/api_json.txt:"
    while read -r code size url; do row "·" "$code" "$size" "$url"; done < recon/api_json.txt
  else
    log "no REAL JSON 200 lead (all hits were gateway errors or HTML shells)."
  fi
  if [ -s recon/api_json_noise.txt ]; then
    log "collapsed $(wc -l < recon/api_json_noise.txt) JSON-200 gateway/error responses as noise → recon/api_json_noise.txt"
  fi
  log "CMS-specific (wp-json, Drupal jsonapi, /actuator/heapdump) = by hand on the CMS hosts, not in a loop."
}

# ---------------------------------------------------------------- -loop js recon: bundle collection (TRAFFIC)
# Downloads the .js (ideal on catch-alls = SPAs: the shell is identical, the real stuff is in the bundles).
# One file per host in js/<host>/. The secret/endpoint TRIAGE stays MANUAL (/7d).
stage_js() {
  local src="${1:-recon/surface_catchall.txt}"   # default SPA; pass surface_ok.txt if you want
  if [ ! -s "$src" ]; then
    warn "no hosts for JS mining ($src empty/absent, e.g. 0 catch-all hosts) → skipping cleanly."
    sub "to mine JS anyway, force a host list:  ~/hunts/bb-recon.sh js recon/surface_ok.txt"
    return 0
  fi
  local n; n=$(wc -l < "$src")
  mkdir -p js
  : > js/_urls.txt

  # PHASE 1 — discover .js URLs. Prefer katana (executes JS, finds dynamic bundles);
  # fall back to the naive crawl (regex on the home page) if katana is absent.
  if have katana; then
    local -a KFLAGS=(); local _cos; _cos="$(_oos_regex)"
    [ -n "$_cos" ] && KFLAGS=(-crawl-out-scope "$_cos")
    log "js recon: katana (crawl with JS execution) over $n hosts, rl $RATE d 2 — more reliable than regex."
    [ -n "$_cos" ] && log "js recon: excluding out-of-scope paths from the crawl (-crawl-out-scope)."
    katana -list "$src" -jc -d 2 -rl "$RATE" "${KFLAGS[@]}" ${PX_HTTPX[@]+"${PX_HTTPX[@]}"} -silent 2>>"$TOOLLOG" \
      | grep -iE '\.(js|mjs)($|\?)' | sort -u > js/_urls.txt || true
  else
    log "js recon: katana absent → naive crawl (regex on the home page) over $n hosts. (Install katana for a lot more.)"
    local i=0
    while read -r u; do
      [ -z "$u" ] && continue
      i=$((i+1)); printf '\r   crawl [%d/%d]' "$i" "$n" >&2
      tcurl -sf "${CT[@]}" "${HDRS[@]}" "$u/" 2>/dev/null \
        | grep -oiE '(src|href)="[^"]+\.(js|mjs)"' | sed -E 's/.*="//; s/"$//' \
        | while read -r j; do case "$j" in /*) echo "$u$j";; http*) echo "$j";; *) echo "$u/$j";; esac; done
    done < "$src" | sort -u > js/_urls.txt
    printf '\r%-30s\r' '' >&2
  fi
  if [ -s recon/oos_paths.txt ]; then
    _oos_filter < js/_urls.txt > js/_urls.tmp && mv js/_urls.tmp js/_urls.txt
  fi
  ok ".js URLs discovered: $(wc -l < js/_urls.txt) → js/_urls.txt"

  # PHASE 2 — download the bundles (host-mapped). -f = don't save error pages as .js.
  local i=0 tot; tot=$(wc -l < js/_urls.txt)
  while read -r j; do
    [ -z "$j" ] && continue
    i=$((i+1)); printf '\r   download [%d/%d]' "$i" "$tot" >&2
    host=$(echo "$j" | sed -E 's#https?://##; s#/.*##'); mkdir -p "js/$host"
    tcurl -sf "${CT[@]}" "${HDRS[@]}" "$j" -o "js/$host/$(echo "$j"|md5sum|cut -c1-8).js" || true
  done < js/_urls.txt
  printf '\r%-30s\r' '' >&2
  find js -type d -empty -delete 2>/dev/null || true   # drop host dirs left empty

  local nf; nf=$(find js -type f -name '*.js' 2>/dev/null | wc -l)
  ok "bundles downloaded: $nf files in js/. Now the TRIAGE is MANUAL (offline, 0 traffic):"
  sub "secret:  grep -rhoiE '(api[_-]?key|client[_-]?secret|access[_-]?token|secret[_-]?key|authorization)' js/"
  sub "srcmap:  find js -name '*.js' -exec tail -c 200 {} + | grep -o 'sourceMappingURL=[^ ]*'"
  sub "pro:     trufflehog filesystem js/   ·   xnLinkFinder -i js/   (offline, fewer false positives)"
  warn "client key ≠ server key: pk_live_/publishable are public by design, NOT a finding. Look for sk_/secret."
}

# ---------------------------------------------------------------- summary (was ffuf-summary, built in)
# Reads the fuzz content/*.json and digests them BY SIZE-CLUSTER within each host:
#   🔴 wall    = a size seen on >= WALL_MIN paths with status 403/3xx (uniform block/redirect) → collapsed
#   🟢 real    = status 200/401, or isolated 3xx/5xx (check the Location)
#   🟡 verify  = 403 with a NON-cluster size (small wall or gated API → by hand)
# 200/401 are NEVER treated as a wall. Wall threshold FIXED = 3 (standard, not configurable).
stage_summary() {
  need jq
  compgen -G "content/*.json" >/dev/null || die "no content/*.json: run 'fuzz' first."
  local WALL_MIN=3                 # fixed: a size on >=3 paths with 403/3xx is a wall
  log "ffuf digest (by size-cluster, wall threshold=$WALL_MIN) from $(ls content/*.json | wc -l) files:"
  jq -rs --argjson wall "$WALL_MIN" '
    def isdeny($s): ($s==403) or ($s>=300 and $s<400);
    def pad($n): tostring | (if length < $n then (" " * ($n - length)) + . else . end);
    # null/empty/truncated ffuf files (a killed job writes "null" or a partial object) must
    # not crash the whole digest: keep only real objects, and treat a missing results[] as [].
    [ .[] | select(type=="object") | (.results // [])[] | select(type=="object") ]
    | group_by(.host)
    | map(
        (.[0].host) as $host
        | ([.[] | select(isdeny(.status))]) as $deny
        | (reduce $deny[] as $r ({}; .[$r.length|tostring] += 1)) as $cnt
        | ([.[] | . + {wall: ( isdeny(.status) and (($cnt[(.length|tostring)]//0) >= $wall) )}]) as $lines
        | { host:$host,
            walls: [ $lines[] | select(.wall) ],
            reals: [ $lines[] | select(.wall|not) ] }
      )
    | sort_by( (.reals|length)==0, .host )
    | .[]
    | "\n== \(.host) ==",
      ( .walls | group_by(.length)[]
        | "     🔴 \(.[0].status|pad(4)) \(.[0].length|pad(9))  wall ×\(length)" ),
      ( .reals | sort_by(.status, .url)[]
        | ( (.["content-type"] // "-" | ascii_downcase | split(";")[0]) // "-" ) as $ct
        | ( if   (.status==200 and ($ct|test("html"))) then "🟡"
            elif (.status==200 or .status==401 or (.status>=300 and .status<400) or (.status>=500)) then "🟢"
            else "🟡" end ) as $ic
        | ( ($ct + "                       ")[0:23] ) as $ctp
        | ( if (.redirectlocation // "") != "" then "  -> " + .redirectlocation else "" end ) as $loc
        | "     \($ic) \(.status|pad(4)) \(.length|pad(9))  \($ctp)  \(.url)\($loc)" )
  ' content/*.json
}

# ---------------------------------------------------------------- report (single HTML, additive, 0 traffic)
# Reads the files the other stages already wrote under $WORK and renders ONE self-contained
# report.html: funnel, ffuf summary (colored), the leads, tool errors, a file index.
# Adds nothing, sends nothing, re-runnable. Answer to "a thousand txt files, I get lost".
stage_report() {
  local OUT="report.html"
  local prog="${PROGRAM:-$(basename "$WORK")}"
  local now; now=$(date '+%Y-%m-%d %H:%M')
  c() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
  local RES LIVE SURF SOK SCA NJS JSF
  RES=$(c recon/resolved.txt); LIVE=$(c recon/live.txt)
  SURF=$(c recon/surface.txt); SOK=$(c recon/surface_ok.txt); SCA=$(c recon/surface_catchall.txt)
  NJS=$(find content -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
  JSF=$(find js -type f -name '*.js' 2>/dev/null | wc -l | tr -d ' ')

  # awk HTML-escaper reused by the emitters below (& < > → entities)
  local ESC='function esc(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}'

  {
    cat <<'HTML_HEAD'
<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>bb-recon report</title>
<style>
body{margin:0;background:#0d1117;color:#c9d1d9;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}.subt{color:#8b949e;margin-bottom:16px;font-size:13px;word-break:break-all}
h2{font-size:16px;border-bottom:1px solid #21262d;padding-bottom:6px;margin:32px 0 8px}
h3.host{font-size:13px;color:#e6edf3;margin:16px 0 4px;font-family:ui-monospace,monospace}
nav{margin:10px 0 4px}nav a{margin-right:14px;font-size:13px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:10px 14px;min-width:88px}
.card .n{font-size:20px;font-weight:600;color:#e6edf3}.card .l{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}
table{border-collapse:collapse;width:100%;margin:6px 0 14px;font-family:ui-monospace,monospace;font-size:13px}
td,th{padding:3px 8px;border-bottom:1px solid #1b2128;text-align:left;vertical-align:top}
td.st{font-weight:600;width:52px}td.sz{color:#8b949e;text-align:right;width:92px;white-space:nowrap}
td.u{word-break:break-all}
tr.wall td{color:#8b949e}
.muted{color:#8b949e}.empty{color:#6e7681;font-style:italic}
ul.hosts{columns:2;font-family:ui-monospace,monospace;font-size:13px;padding-left:18px}
@media(max-width:640px){ul.hosts{columns:1}}
pre{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:10px;overflow:auto;white-space:pre-wrap;word-break:break-word;font-size:12px}
.legend{color:#8b949e;font-size:12px;margin:4px 0 0}
</style></head><body><div class=wrap>
HTML_HEAD

    printf '<h1>bb-recon — %s</h1>\n' "$(esc "$prog")"
    printf '<div class=subt>%s · %s</div>\n' "$(esc "$now")" "$(esc "$WORK")"
    echo '<nav><a href="#funnel">Funnel</a><a href="#summary">Summary</a><a href="#leads">Leads</a><a href="#errors">Errors</a><a href="#files">Files</a></nav>'

    # ---- funnel ----
    echo '<h2 id=funnel>Funnel</h2><div class=cards>'
    printf '<div class=card><div class=n>%s</div><div class=l>%s</div></div>\n' \
      "$RES" resolve "$LIVE" live "$SURF" surface "$SOK" surface_ok "$SCA" catch-all \
      "$(c recon/browser_todo.txt)" browser_todo "$NJS" "ffuf files" "$JSF" "js bundles"
    echo '</div>'

    # ---- ffuf summary (colored) ----
    echo '<h2 id=summary>ffuf summary</h2>'
    echo '<p class=legend>🟢 real · 🟡 verify (200 text/html = pagina/SPA, non un file) · 🔴 wall (collapsed cluster) — wall threshold = 3</p>'
    if have jq && compgen -G "content/*.json" >/dev/null 2>&1; then
      jq -rs --argjson wall 3 '
        def isdeny($s): ($s==403) or ($s>=300 and $s<400);
        # tolerate null/empty/truncated ffuf files so one bad file never breaks the report
        [ .[] | select(type=="object") | (.results // [])[] | select(type=="object") ]
        | group_by(.host)
        | map( (.[0].host) as $host
            | ([.[]|select(isdeny(.status))]) as $deny
            | (reduce $deny[] as $r ({}; .[$r.length|tostring]+=1)) as $cnt
            | ([.[]| . + {wall:( isdeny(.status) and (($cnt[(.length|tostring)]//0)>=$wall))}]) as $lines
            | {host:$host, walls:[$lines[]|select(.wall)], reals:[$lines[]|select(.wall|not)]} )
        | sort_by((.reals|length)==0, .host)
        | .[]
        | "<h3 class=host>\(.host|@html)</h3><table>",
          (.walls|group_by(.length)[]
            | "<tr class=wall><td>🔴</td><td class=st>\(.[0].status)</td><td class=sz>\(.[0].length)</td><td>wall ×\(length)</td></tr>"),
          (.reals|sort_by(.status,.url)[]
            | ((.["content-type"]//"-" | ascii_downcase | split(";")[0]) // "-") as $ct
            | (if   (.status==200 and ($ct|test("html"))) then "🟡"
               elif (.status==200 or .status==401 or (.status>=300 and .status<400) or (.status>=500)) then "🟢"
               else "🟡" end) as $ic
            | (if (.redirectlocation//"")!="" then " <span class=muted>-&gt; "+(.redirectlocation|@html)+"</span>" else "" end) as $loc
            | "<tr><td>\($ic)</td><td class=st>\(.status)</td><td class=sz>\(.length)</td><td class=u><span class=muted>\($ct|@html)</span> <a href=\"\(.url|@html)\">\(.url|@html)</a>\($loc)</td></tr>"),
          "</table>"
      ' content/*.json
    else
      echo '<p class=empty>fuzz not run (no content/*.json) or jq missing.</p>'
    fi

    # ---- leads ----
    echo '<h2 id=leads>Leads</h2>'
    local had_lead=0

    if [ -s recon/api_json.txt ]; then had_lead=1
      printf '<h3 class=host>APIs returning JSON 200 <span class=muted>(%s)</span></h3><table>\n' "$(c recon/api_json.txt)"
      awk "$ESC"'{printf "<tr><td class=st>%s</td><td class=sz>%s</td><td class=u><a href=\"%s\">%s</a></td></tr>\n",$1,$2,esc($3),esc($3)}' recon/api_json.txt
      echo '</table>'
    fi
    if [ -s recon/quickhits_auth.txt ]; then had_lead=1
      printf '<h3 class=host>401 / 403-gated (APIs asking for auth) <span class=muted>(%s)</span></h3><table>\n' "$(c recon/quickhits_auth.txt)"
      awk "$ESC"'/^403-gated /{printf "<tr><td class=st>403</td><td class=sz>gated</td><td class=u>%s</td></tr>\n",esc($2);next}
                 {st=$2;sz=$3;gsub(/[][]/,"",st);gsub(/[][]/,"",sz);printf "<tr><td class=st>%s</td><td class=sz>%s</td><td class=u><a href=\"%s\">%s</a></td></tr>\n",st,sz,esc($1),esc($1)}' recon/quickhits_auth.txt
      echo '</table>'
    fi
    if [ -s recon/quickhits_interesting.txt ]; then had_lead=1
      printf '<h3 class=host>Paths with an odd size <span class=muted>(%s)</span></h3><table>\n' "$(c recon/quickhits_interesting.txt)"
      awk "$ESC"'{st=$2;sz=$3;gsub(/[][]/,"",st);gsub(/[][]/,"",sz);printf "<tr><td class=st>%s</td><td class=sz>%s</td><td class=u><a href=\"%s\">%s</a></td></tr>\n",st,sz,esc($1),esc($1)}' recon/quickhits_interesting.txt
      echo '</table>'
    fi
    if [ -s recon/rescued.txt ]; then had_lead=1
      printf '<h3 class=host>Root-404 hosts that speak (API/auth/infra) <span class=muted>(%s)</span></h3><table>\n' "$(c recon/rescued.txt)"
      awk "$ESC"'{u=$1;rest=substr($0,length($1)+2);printf "<tr><td class=u><a href=\"%s\">%s</a></td><td class=muted>%s</td></tr>\n",esc(u),esc(u),esc(rest)}' recon/rescued.txt
      echo '</table>'
    fi
    if [ -s recon/robots_targets.txt ]; then had_lead=1
      printf '<h3 class=host>Explicit targets from robots <span class=muted>(%s)</span></h3><ul class=hosts>\n' "$(c recon/robots_targets.txt)"
      awk "$ESC"'{printf "<li><a href=\"%s\">%s</a></li>\n",esc($1),esc($1)}' recon/robots_targets.txt
      echo '</ul>'
    fi
    if [ -s recon/browser_todo.txt ]; then had_lead=1
      printf '<h3 class=host>CF walls — open BY HAND in the browser <span class=muted>(%s)</span></h3><ul class=hosts>\n' "$(c recon/browser_todo.txt)"
      awk "$ESC"'{printf "<li><a href=\"%s\">%s</a></li>\n",esc($1),esc($1)}' recon/browser_todo.txt
      echo '</ul>'
    fi
    [ "$had_lead" -eq 0 ] && echo '<p class=empty>No automatic leads (normal on mature targets). Check the summary and the js/ bundles by hand.</p>'

    # ---- tool errors ----
    echo '<h2 id=errors>Tool errors (notes/tools.log)</h2>'
    if [ -f notes/tools.log ] && grep -iqE '\[err\]|\bEOF\b|panic|fatal' notes/tools.log 2>/dev/null; then
      echo '<pre>'
      grep -iE '\[err\]|\bEOF\b|panic|fatal' notes/tools.log | sort -u | head -40 \
        | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'
      echo '</pre><p class=muted>Often = WAF/anti-bot dropping the tools on a host → move it to browser_todo, don&#39;t hammer.</p>'
    else
      echo '<p class=empty>No obvious tool errors.</p>'
    fi

    # ---- file index ----
    echo '<h2 id=files>Files</h2><table><tr><th>file</th><th class=sz>lines</th></tr>'
    local f
    for f in recon/subs_all.txt recon/subs_inscope.txt recon/resolved.txt recon/live.txt \
             recon/surface.txt recon/browser_todo.txt recon/rescued.txt recon/discarded.txt \
             recon/surface_ok.txt recon/surface_catchall.txt recon/quickhits.txt \
             recon/quickhits_interesting.txt recon/quickhits_auth.txt recon/robots_urls.txt \
             recon/robots_paths.txt recon/robots_targets.txt recon/sitemap_urls.txt recon/api_json.txt; do
      [ -f "$f" ] && printf '<tr><td>%s</td><td class=sz>%s</td></tr>\n' "$f" "$(c "$f")"
    done
    printf '<tr><td>content/*.json</td><td class=sz>%s</td></tr>\n' "$NJS"
    printf '<tr><td>js/**/*.js</td><td class=sz>%s</td></tr>\n' "$JSF"
    echo '</table>'

    echo '</div></body></html>'
  } > "$OUT"
  ok "report written → $WORK/$OUT (open it in a browser)"
}

# ---------------------------------------------------------------- all (orchestrator: the whole pipeline on its own)
# Runs ALL stages in sequence, check → js, asking nothing. This is the normal use:
# give the parameters once (via env.sh / bb-init) and go. Single stages remain for test/debug.
# Each stage runs in a subshell: if one fails (missing tool, empty input) the pipeline does NOT
# stop, it logs and moves on — so a "launch and walk away" run always reaches the end.
run_stage() {
  local s="$1"; shift || true
  # proxy died mid-run? re-check before any target-hitting stage and stop clean (NOT inside the
  # subshell below — a die there would only be caught and the pipeline would carry on blind).
  proxy_guard "$s"
  printf '\n\033[1;35m━━━━━━━━━━━━━━  %s  ━━━━━━━━━━━━━━\033[0m\n' "$s" >&2
  # NB: '( ... ) || rc=$?' and NOT '( ... ); rc=$?' — under 'set -e' a failing subshell
  # aborts the parent BEFORE the next command, so the ';' form would kill the whole pipeline
  # on the first stage whose last command returns non-zero. The '||' exempts it from set -e.
  local rc=0
  ( "stage_$s" "$@" ) || rc=$?
  [ "$rc" -eq 0 ] || warn "stage '$s' aborted (rc=$rc) — moving on to the next."
  return 0
}
stage_all() {
  : > "$TOOLLOG"    # fresh tools log for this run
  log "FULL PIPELINE — rate=$RATE"
  run_stage check
  run_stage enum
  run_stage live
  run_stage triage
  run_stage catchall
  run_stage quickhits
  run_stage harvest
  run_stage fuzz
  run_stage summary
  run_stage api
  run_stage js
  run_stage report
  log "FULL PIPELINE done. Open the report: $WORK/report.html"
}

# ---------------------------------------------------------------- dispatcher
usage() {
  sed -n '2,40p' "$SELF" >&2
  exit 1
}
[ "$#" -ge 1 ] || usage
stage="$1"; shift || true
# single-stage runs (how `kestrel recon` drives the engine) skip run_stage, so guard here too.
# For 'all', _proxied_stage is false, so this is a no-op and run_stage guards each stage instead.
proxy_guard "$stage"
case "$stage" in
  check)     stage_check "$@" ;;
  enum)      stage_enum "$@" ;;
  live)      stage_live "$@" ;;
  triage)    stage_triage "$@" ;;
  catchall)  stage_catchall "$@" ;;
  quickhits) stage_quickhits "$@" ;;
  harvest)   stage_harvest "$@" ;;
  fuzz)      stage_fuzz "$@" ;;
  summary)   stage_summary "$@" ;;
  api)       stage_api "$@" ;;
  js)        stage_js "$@" ;;
  report)    stage_report "$@" ;;
  all)       stage_all "$@" ;;
  -h|--help|help) usage ;;
  *) die "unknown stage: '$stage'. Available: all, check, enum, live, triage, catchall, quickhits, harvest, fuzz, summary, api, js, report." ;;
esac
log "stage '$stage' done."
