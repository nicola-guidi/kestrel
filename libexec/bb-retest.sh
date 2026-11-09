#!/usr/bin/env bash
# bb-retest.sh — INCREMENTAL re-recon: find assets that are NEW since the last full scan.
#
# The full scan (bb-recon all) is run ONCE. Later you run this: it re-enumerates the
# wildcard apex, compares against a saved baseline, and tells you ONLY what appeared since.
# New subs are then resolved and probed (httpx) so you immediately see which newcomers are
# live — the heavy per-host stages (fuzz/api/js) stay for you to run on the few new hosts.
#
# It does NOT touch the main recon files. Everything lands under recon/retest/.
# Reuses the same env as bb-recon:  source env.sh first.
#
# Usage:
#   source ~/hunts/<prog>/env.sh && ~/hunts/bb-retest.sh
#   ~/hunts/bb-retest.sh ~/hunts/<prog>        # or pass the folder
#
# First run: seeds the baseline from the full scan (recon/subs_inscope.txt) and reports
# "baseline saved". From the second run on, it reports the delta.
set -euo pipefail
# Force C locale so 'sort' and 'comm' agree on byte collation. Without it a locale-aware
# sort and comm can disagree on order → comm prints "not in sorted order" and exits non-zero,
# which under 'set -e' would abort the whole retest. Hostnames are ASCII, so C is safe.
export LC_ALL=C

# ---------------------------------------------------------------- output helpers
log()  { printf '\033[1;36m[bb-retest %s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()   { printf '   \033[1;32m✓\033[0m %s\n' "$*" >&2; }
warn() { printf '   \033[1;33m⚠\033[0m  %s\n' "$*" >&2; }
sub()  { printf '     \033[2m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[bb-retest] ✗ %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" || die "missing '$1' in PATH."; }

# ---------------------------------------------------------------- flags
# DEEP (default ON): after the new live hosts are found, run the per-host pipeline
# (live→triage→catchall→quickhits→harvest→fuzz→summary→api→js) on JUST those hosts,
# isolated under the retest run folder. '--shallow' (or '--no-deep') stops at new_live.
DEEP=1
_args=()
for _a in "$@"; do
  case "$_a" in
    --deep)              DEEP=1 ;;
    --shallow|--no-deep) DEEP=0 ;;
    *)                   _args+=("$_a") ;;
  esac
done
if [ "${#_args[@]}" -gt 0 ]; then set -- "${_args[@]}"; else set --; fi

# ---------------------------------------------------------------- find the program folder
WORK="${1:-${WORK:-}}"
[ -z "$WORK" ] && [ -n "${PROGRAM:-}" ] && WORK="$HOME/hunts/$PROGRAM"
if [ -z "$WORK" ] || [ ! -d "$WORK" ]; then
  die "program folder not found. Run:  source ~/hunts/<prog>/env.sh && ~/hunts/bb-retest.sh"
fi
cd "$WORK"
mkdir -p recon recon/retest notes

# ---------------------------------------------------------------- config (same knobs as bb-recon)
: "${APEX_FILE:=$WORK/recon/apex.txt}"
: "${OOS_FILE:=$WORK/recon/oos.txt}"
: "${UA:=Mozilla/5.0}"
: "${YWH:=}"
: "${RATE:=5}"
: "${DNS_RESOLVERS:=1.1.1.1,8.8.8.8,9.9.9.9}"
: "${DNS_RATE:=100}"
: "${DNS_THREADS:=40}"
: "${DNS_CHUNK:=3000}"
: "${DNS_PAUSE:=20}"
: "${TOOLLOG:=$WORK/notes/tools.log}"

# Ephemeral infra noise in cert-transparency SANs (big orgs churn these by the thousand):
#   IP-literal labels  128.149.171.29.jpl… / 100-64-20-125.jpl…
#   MAC-address labels 00-50-b6-c3-6f-20.ndc…
#   UUID labels        50ad5d99-bc16-4314-ab7e-064a3eb7c841.development.luna…
# They are not real "new assets", so drop them from both sides of the diff. Run with NOISE='' to keep them.
# NOTE: set with a plain single-quoted assignment, NOT `${NOISE:=...}` — the first `}` of a `{1,3}`
# quantifier would close the parameter expansion early and silently truncate the regex.
if [ -z "${NOISE+set}" ]; then
  NOISE='^[0-9]{1,3}[.-][0-9]{1,3}[.-][0-9]{1,3}[.-][0-9]{1,3}\.|^([0-9a-f]{2}-){5}[0-9a-f]{2}\.|^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.'
fi
# drop_noise <infile> <outfile>: strip the above (no-op if NOISE is empty)
drop_noise() {
  if [ -n "$NOISE" ]; then grep -ivE "$NOISE" "$1" > "$2" || true; else cp "$1" "$2"; fi
}

# identification header, only if it's a real "Name: value"
HDRS=(-H "User-Agent: $UA")
if [ -n "$YWH" ]; then
  case "$YWH" in
    *:*) HDRS+=(-H "$YWH") ;;
    *)   warn "ignoring malformed identification '$YWH' (not a 'Name: value' header)." ;;
  esac
fi
# kestrel: every extra custom header from the program's headers.txt (one "Name: value" per line)
if [ -n "${HEADERS_FILE:-}" ] && [ -s "$HEADERS_FILE" ]; then
  while IFS= read -r _h || [ -n "$_h" ]; do
    case "$_h" in *:*) [ "$_h" = "$YWH" ] || HDRS+=(-H "$_h") ;; esac
  done < "$HEADERS_FILE"
fi

BASE="recon/retest/baseline_subs.txt"              # the known universe of in-scope subs
STAMP="$(date +%Y%m%d_%H%M)"
RDIR="recon/retest/$STAMP"                          # this run's output folder
mkdir -p "$RDIR"

[ -s "$APEX_FILE" ] || die "no wildcard apex ($APEX_FILE empty). Incremental retest only makes sense on a wildcard scope."

# ---------------------------------------------------------------- 1. seed baseline on first run
# Prefer the original full scan's in-scope subs as the starting point, so the FIRST retest
# already compares against the real full scan — then it continues straight into the diff
# below (no separate "make baseline" run needed).
if [ ! -f "$BASE" ]; then
  if [ -s recon/subs_inscope.txt ]; then
    sed -E 's/^[*.]+//' recon/subs_inscope.txt | sort -u > "$BASE"
    ok "baseline seeded=$(wc -l < "$BASE") → $BASE"
    log "first retest: comparing a fresh enumeration against the full scan now"
  else
    : > "$BASE"
    warn "no recon/subs_inscope.txt (full scan not found): starting from an EMPTY baseline."
    warn "This first retest will treat everything it finds as 'new'. That's expected once."
  fi
fi

# normalize the baseline every run: strip leftover '*.'/'.' from crt.sh wildcard cert entries
# (e.g. '*.arc.nasa.gov' → 'arc.nasa.gov'). Makes a baseline seeded by an older/buggy
# enumeration self-heal, so the diff compares clean hostnames and stops inventing fake "new" subs.
_bt=$(mktemp); _bt2=$(mktemp)
sed -E 's/^[*.]+//' "$BASE" | sort -u > "$_bt"
drop_noise "$_bt" "$_bt2"; sort -u "$_bt2" -o "$_bt2"
[ -s "$_bt2" ] && mv "$_bt2" "$BASE"; rm -f "$_bt" "$_bt2"

# ---------------------------------------------------------------- 2. re-enumerate NOW
need subfinder
log "re-enumerating $(wc -l < "$APEX_FILE") apex (subfinder + crt.sh)"
while read -r d; do
  [ -z "$d" ] && continue
  subfinder -d "$d" -silent 2>>"$TOOLLOG" || true
  curl -s --connect-timeout 10 --max-time 40 "${HDRS[@]}" "https://crt.sh/?q=%25.$d&output=json" \
    | grep -oE "[a-zA-Z0-9._-]+\.$d" || true
done < "$APEX_FILE" | sed -E 's/^[*.]+//' | sort -u > "$RDIR/subs_now_all.txt"

# out-of-scope filter (same as enum)
if [ -s "$OOS_FILE" ]; then
  grep -vFf "$OOS_FILE" "$RDIR/subs_now_all.txt" > "$RDIR/subs_now.txt" || true
else
  cp "$RDIR/subs_now_all.txt" "$RDIR/subs_now.txt"
fi
drop_noise "$RDIR/subs_now.txt" "$RDIR/subs_now.tmp"
sort -u "$RDIR/subs_now.tmp" -o "$RDIR/subs_now.tmp"
mv "$RDIR/subs_now.tmp" "$RDIR/subs_now.txt"
ok "subs_now=$(wc -l < "$RDIR/subs_now.txt") → $RDIR/subs_now.txt"

# ---------------------------------------------------------------- 3. the delta (what's NEW)
comm -13 "$BASE" "$RDIR/subs_now.txt" > "$RDIR/new_subs.txt"
GONE="$RDIR/gone_subs.txt"
comm -23 "$BASE" "$RDIR/subs_now.txt" > "$GONE"      # info only: disappeared since baseline
NEW=$(wc -l < "$RDIR/new_subs.txt")
ok "new_subs=$NEW → $RDIR/new_subs.txt"
[ -s "$GONE" ] && sub "gone=$(wc -l < "$GONE") → $GONE"

if [ "$NEW" -eq 0 ]; then
  log "nothing new. Baseline unchanged. Done."
  exit 0
fi

# ---------------------------------------------------------------- 4. resolve only the newcomers (chunked)
if have dnsx; then
  : > "$RDIR/new_resolved.txt"
  if [ "$DNS_CHUNK" -gt 0 ] && [ "$NEW" -gt "$DNS_CHUNK" ]; then
    log "dnsx: chunked resolve of $NEW new subs (rl $DNS_RATE, chunk $DNS_CHUNK)"
    split -l "$DNS_CHUNK" -d "$RDIR/new_subs.txt" "$RDIR/_part_"
    i=0; done=0
    for part in "$RDIR"/_part_*; do
      i=$((i+1)); done=$((done+$(wc -l < "$part")))
      dnsx -l "$part" -r "$DNS_RESOLVERS" -rl "$DNS_RATE" -t "$DNS_THREADS" -silent >> "$RDIR/new_resolved.txt" 2>>"$TOOLLOG" || true
      printf '\r   resolve %d/%d · ok %d' "$done" "$NEW" "$(wc -l < "$RDIR/new_resolved.txt")" >&2
      [ "$done" -lt "$NEW" ] && sleep "$DNS_PAUSE"
    done
    printf '\r%-60s\r' '' >&2
    rm -f "$RDIR"/_part_*
  else
    log "dnsx on the $NEW new subs (rl $DNS_RATE)"
    dnsx -l "$RDIR/new_subs.txt" -r "$DNS_RESOLVERS" -rl "$DNS_RATE" -t "$DNS_THREADS" -silent > "$RDIR/new_resolved.txt" 2>>"$TOOLLOG" || true
  fi
  sort -u "$RDIR/new_resolved.txt" -o "$RDIR/new_resolved.txt"
  ok "new_resolved=$(wc -l < "$RDIR/new_resolved.txt") → $RDIR/new_resolved.txt"
else
  warn "dnsx missing: skipping resolve; probing new_subs.txt directly."
  cp "$RDIR/new_subs.txt" "$RDIR/new_resolved.txt"
fi

# ---------------------------------------------------------------- 5. probe the new live hosts
if [ -s "$RDIR/new_resolved.txt" ]; then
  need httpx
  log "httpx on $(wc -l < "$RDIR/new_resolved.txt") newcomers (rl $RATE)"
  httpx -l "$RDIR/new_resolved.txt" "${HDRS[@]}" \
    -sc -title -td -server -cl -location \
    -r "$DNS_RESOLVERS" \
    -t 50 -timeout 5 -retries 1 -rl "$RATE" -silent \
    -o "$RDIR/new_live.txt" >>"$TOOLLOG" 2>&1 || true
  touch "$RDIR/new_live.txt"
  ok "new_live=$(wc -l < "$RDIR/new_live.txt") → $RDIR/new_live.txt"
fi

# ---------------------------------------------------------------- 6. refresh the baseline
# Union: next time, only things newer than today count as new.
sort -u "$BASE" "$RDIR/subs_now.txt" -o "$BASE"
ok "baseline updated=$(wc -l < "$BASE") → $BASE"

# ---------------------------------------------------------------- 7. deep-test the new live hosts
# By default, run the full per-host pipeline on JUST the newcomers, in an ISOLATED workspace
# under the retest folder (hosts-only scope: empty apex → enum skipped). The main recon/ is
# never touched. '--shallow' stops here and leaves the per-host stages for you to run by hand.
if [ "$DEEP" -eq 1 ] && [ -s "$RDIR/new_live.txt" ]; then
  RECON_BIN="$(cd "$(dirname "$0")" && pwd)/bb-recon.sh"
  if [ ! -f "$RECON_BIN" ]; then
    warn "deep: bb-recon.sh not found next to bb-retest ($RECON_BIN). Deep-test by hand on $RDIR/new_live.txt."
    log "retest done. Full output in $WORK/$RDIR/"
  else
    DEEP_DIR="$RDIR/deep"
    mkdir -p "$DEEP_DIR/recon" "$DEEP_DIR/content" "$DEEP_DIR/js" "$DEEP_DIR/notes"
    DEEP_ABS="$(cd "$DEEP_DIR" && pwd)"                  # absolute: bb-recon cd's into WORK, then builds ${WORK}/… paths
    # bare hostnames from the new live hosts → isolated hosts-only workspace
    sed -E 's#^https?://##; s#[[:space:]].*$##; s#[/:].*$##' "$RDIR/new_live.txt" | sort -u > "$DEEP_ABS/recon/hosts.txt"
    : > "$DEEP_ABS/recon/apex.txt"                       # empty apex → bb-recon skips enum (hosts-only scope)
    [ -s "$OOS_FILE" ] && cp "$OOS_FILE" "$DEEP_ABS/recon/oos.txt"
    # REUSE the probe we already did: new_live.txt is produced with the SAME httpx flags as
    # bb-recon's 'live' stage, so it IS a valid recon/live.txt. Seed it and start at 'triage' —
    # no second resolve/httpx of the same hosts.
    cp "$RDIR/new_live.txt" "$DEEP_ABS/recon/live.txt"
    log "deep: per-host pipeline on $(wc -l < "$DEEP_ABS/recon/hosts.txt") new host(s), isolated (main recon untouched)"
    for st in triage catchall quickhits harvest fuzz summary api js; do
      log "deep: $st"
      # On the deep set (few hosts) mine JS on ALL live new hosts, not just catch-alls.
      starg=""; [ "$st" = js ] && starg="recon/surface_ok.txt"
      # Override EVERY path var: env.sh exports SUBS/INSCOPE/APEX_FILE/OOS_FILE pointing at the
      # MAIN program, and those would otherwise leak in and make bb-recon re-scan all 133k subs.
      # Pin them (and TOOLLOG) to the isolated deep workspace so only the new hosts are tested.
      WORK="$DEEP_ABS" \
      SUBS="$DEEP_ABS/recon/subs_all.txt" \
      INSCOPE="$DEEP_ABS/recon/subs_inscope.txt" \
      APEX_FILE="$DEEP_ABS/recon/apex.txt" \
      OOS_FILE="$DEEP_ABS/recon/oos.txt" \
      TOOLLOG="$DEEP_ABS/notes/tools.log" \
      bash "$RECON_BIN" "$st" $starg || warn "deep: stage '$st' reported issues (see $DEEP_ABS/notes/tools.log)"
    done
    ok "deep done → $DEEP_DIR/"
    log "retest done. New live: $RDIR/new_live.txt · deep: $DEEP_DIR/"
  fi
else
  if [ "$DEEP" -eq 0 ]; then
    log "shallow mode: stopped at new_live. Deep-test the newcomers by hand:"
    sub "cp $RDIR/new_live.txt recon/hosts.txt   # (back up your real hosts.txt first if you use one)"
    sub "then the per-host stages: triage → catchall → quickhits → fuzz → api → js"
  fi
  log "retest done. Full output in $WORK/$RDIR/"
fi
