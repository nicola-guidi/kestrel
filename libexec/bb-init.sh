#!/usr/bin/env bash
#
# bb-init.sh — PHASE 0 (Scope & Setup), interactive, for a new bug-bounty program.
# Creates ~/hunts/<program>/{recon,content,js,notes}, a unified scope.txt, and an
# env.sh with the variables to re-use each session (source env.sh). At the end it can
# launch the whole recon (bb-recon.sh all) so you set the parameters once and walk away.
#
# Unified scope model (one scope.txt, mixed scopes supported):
#   *.domain   → wildcard  → apex.txt  → enumerated by 'enum' (subfinder + crt.sh)
#   host.full  → single host → hosts.txt → used as-is, straight into 'live'
#   IP / CIDR  → cidr_inscope.txt (v4/v6)  → for bb-ports --ranges
# Out-of-scope IP/CIDR go to cidr_oos.txt; ip_targets.txt = in-scope ranges MINUS OOS ranges
# (computed here, ready for bb-ports --ranges).
# A program with BOTH wildcards and standalone hosts just works.
#
# Usage:  bash bb-init.sh
#
set -euo pipefail

# --- helpers --------------------------------------------------------------
ask()       { local p="$1" d="${2:-}"; local a; read -r -p "$p${d:+ [$d]}: " a; echo "${a:-$d}"; }
ask_multi() { # read lines until an empty one; print one per line
  local p="$1" line
  echo "$p (one per line, empty ENTER to finish):" >&2
  while IFS= read -r line; do [ -z "$line" ] && break; echo "$line"; done
}

echo "=========================================="
echo "  PHASE 0 — new bug-bounty program setup"
echo "=========================================="

# --- program identity -----------------------------------------------------
PROGRAM="$(ask 'Program name (= folder name, e.g. dropxl)')"
[ -z "$PROGRAM" ] && { echo "A program name is required."; exit 1; }
BASE_DIR="${BB_BASE:-$HOME/hunts}"
WORK="$BASE_DIR/$PROGRAM"

# --- required identification (string appended to UA vs separate header) ----
echo
echo "How does the program want you to identify?"
echo "  1) string APPENDED to the User-Agent   (e.g. ' -BugBounty-xxx-31337 ')"
echo "  2) separate HTTP HEADER                (e.g. 'X-Program-Research: your_user')"
echo "  3) none"
IDTYPE="$(ask 'Choice 1/2/3' '3')"
UA='Mozilla/5.0'
YWH=''
case "$IDTYPE" in
  1) IDVAL="$(ask 'String to append to the UA (no quotes)')"; UA="Mozilla/5.0 ${IDVAL}";;
  2) YWH="$(ask 'Full header (Name: value)')"
     # a real header needs a colon. A value without one (e.g. a '-BugBounty-xxx' identifier)
     # belongs in the User-Agent (option 1): as a header it breaks httpx/curl. Auto-recover.
     case "$YWH" in
       *:*) : ;;
       '')  : ;;
       *)   echo "  ⚠ '$YWH' is not a 'Name: value' header (no colon)."
            echo "    Identifiers like '-BugBounty-xxx' go in the User-Agent, not as a header."
            m="$(ask 'Append it to the User-Agent instead? y/N' 'y')"
            if printf '%s' "$m" | grep -qiE '^y'; then UA="Mozilla/5.0 ${YWH}"; YWH=''; echo "    -> moved to UA."; fi ;;
     esac ;;
  *) : ;;
esac

# --- create folder structure ---------------------------------------------
mkdir -p "$WORK"/{recon,content,js,notes}

# ============================================================================
# SCOPE — two sections, each with IN scope and OUT of scope:
#   A) hostnames & wildcards  → apex.txt / hosts.txt / oos.txt     (bb-recon)
#   B) IPs & ranges           → cidr_inscope.txt / cidr_oos.txt    (bb-ports --ranges)
#      + ip_targets.txt = in-scope ranges MINUS out-of-scope ranges
# ============================================================================
SCOPE_FILE="$WORK/recon/scope.txt"
APEX_FILE="$WORK/recon/apex.txt"
HOSTS_FILE="$WORK/recon/hosts.txt"
OOS_FILE="$WORK/recon/oos.txt"
CIDR_IN="$WORK/recon/cidr_inscope.txt"
CIDR_OOS="$WORK/recon/cidr_oos.txt"
IP_TARGETS="$WORK/recon/ip_targets.txt"
# awk test for an IP or CIDR line (v4 or v6)
IPTEST='line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?$/ || line ~ /^[0-9a-fA-F]*:[0-9a-fA-F]*:[0-9a-fA-F:]*(\/[0-9]+)?$/'

echo
echo "────────── A) HOSTNAMES & WILDCARDS ──────────"
echo "IN SCOPE:"
echo "  *.domain   → wildcard (will be enumerated)"
echo "  host.full  → single host (used as-is)"
ask_multi "Hostnames/wildcards IN scope" > "$SCOPE_FILE"

# apex.txt (wildcards, stripped of '*.') + hosts.txt (scheme/path stripped).
# An IP/CIDR typed here by mistake is routed to section B, never into hosts.txt.
: > "$CIDR_IN"
awk "
  { line=\$0; gsub(/^[ \t]+|[ \t]+\$/,\"\",line) }
  line==\"\" { next }
  $IPTEST { print line > cidr; next }
  line ~ /^\*\./ { sub(/^\*\./,\"\",line); print line > apex; next }
  { sub(/^https?:\/\//,\"\",line); sub(/\/.*\$/,\"\",line); if (line!=\"\") print line > hosts }
" apex="$APEX_FILE" hosts="$HOSTS_FILE" cidr="$CIDR_IN" "$SCOPE_FILE"
touch "$APEX_FILE" "$HOSTS_FILE"
sort -u "$APEX_FILE"  -o "$APEX_FILE"  2>/dev/null || true
sort -u "$HOSTS_FILE" -o "$HOSTS_FILE" 2>/dev/null || true
[ -s "$CIDR_IN" ] && echo "  (moved $(wc -l < "$CIDR_IN") IP/CIDR entr(y/ies) to section B)"
echo "  -> wildcard apex: $(wc -l < "$APEX_FILE")  ·  standalone hosts: $(wc -l < "$HOSTS_FILE")"

echo
echo "OUT OF SCOPE (from the brief) — whole hosts or words:"
echo "  e.g.  old.example.com   staging   sandbox   (short/ambiguous word like dev → use -dev.)"
echo "  (empty = nothing to exclude)"
: > "$CIDR_OOS"
ask_multi "Hostnames/wildcards OUT of scope" | awk "
  { line=\$0; gsub(/^[ \t]+|[ \t]+\$/,\"\",line) }
  line==\"\" { next }
  $IPTEST { print line > cidr; next }
  { sub(/^\*\./,\"\",line); print line }
" cidr="$CIDR_OOS" > "$OOS_FILE"
if [ -s "$OOS_FILE" ]; then echo "  -> $(wc -l < "$OOS_FILE") entries in $OOS_FILE"; else echo "  -> no out-of-scope (ok)"; fi

echo
echo "────────── B) IPs & RANGES ──────────"
echo "IN SCOPE — single IPs or CIDR, v4 or v6  (e.g. 203.0.113.7   10.0.0.0/16   2001:db8::/48)"
echo "  (empty = the program has no IP ranges)"
# read_ips <dest>: append valid IP/CIDR lines to <dest>, warn and skip anything else
read_ips() {
  ask_multi "$1" | awk "
    { line=\$0; gsub(/^[ \t]+|[ \t]+\$/,\"\",line) }
    line==\"\" { next }
    $IPTEST { print line; next }
    { print \"  ⚠ not an IP/CIDR, skipped: \" line > \"/dev/stderr\" }
  " >> "$2"
}
read_ips "IPs/ranges IN scope" "$CIDR_IN"
sort -u "$CIDR_IN" -o "$CIDR_IN"
echo
echo "OUT OF SCOPE — IPs or CIDR to NEVER touch, even inside an in-scope range (e.g. 10.0.188.0/22)"
read_ips "IPs/ranges OUT of scope" "$CIDR_OOS"
sort -u "$CIDR_OOS" -o "$CIDR_OOS"

# ip_targets.txt = in-scope ranges MINUS out-of-scope ranges (what bb-ports --ranges scans)
: > "$IP_TARGETS"
if [ -s "$CIDR_IN" ]; then
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$CIDR_IN" "$CIDR_OOS" > "$IP_TARGETS" <<'PY' || echo "  ⚠ could not compute $IP_TARGETS (check the IP/CIDR syntax)"
import sys, ipaddress as I
rd = lambda f: [I.ip_network(l.strip(), strict=False) for l in open(f) if l.strip()]
ins, oos = rd(sys.argv[1]), rd(sys.argv[2])
for n in ins:
    if n.version == 6 and n.prefixlen < 112:
        print(f"  ! {n}: IPv6 range too large to scan, left out (test only known v6 hosts)", file=sys.stderr)
        continue
    parts = [n]
    for e in oos:
        parts = [q for p in parts for q in (p.address_exclude(e) if e.version == p.version and e.subnet_of(p) else [p])]
    for p in parts: print(p)
PY
    NADDR=$(python3 -c "import sys,ipaddress as I;print(sum(I.ip_network(l.strip()).num_addresses for l in open(sys.argv[1]) if l.strip()))" "$IP_TARGETS" 2>/dev/null || echo '?')
    echo "  -> in scope: $(wc -l < "$CIDR_IN") · out of scope: $(wc -l < "$CIDR_OOS") · to scan: $(wc -l < "$IP_TARGETS") range(s), $NADDR IP(s) → $IP_TARGETS"
  else
    echo "  ⚠ python3 not found: $IP_TARGETS not computed (needed by bb-ports --ranges)."
  fi
else
  echo "  -> no IP ranges in scope"
fi

if [ ! -s "$APEX_FILE" ] && [ ! -s "$HOSTS_FILE" ] && [ ! -s "$CIDR_IN" ]; then
  echo "Empty scope: at least one hostname, wildcard or IP range is required."; exit 1
fi

# --- rate limit + wordlist ------------------------------------------------
echo
RATE="$(ask 'Rate limit (requests/sec for the fast tools: httpx/ffuf/katana/dnsx)' '5')"
CURATED="$(ask 'Curated wordlist path (for fuzz)' "$HOME/hunts/wordlists/curated.txt")"
[ -s "$CURATED" ] || echo "  ⚠ note: $CURATED not found yet — put it there before 'fuzz' runs."

# --- write env.sh ---------------------------------------------------------
cat > "$WORK/env.sh" <<ENV
# Session variables for: $PROGRAM  (source this file each session)
export PROGRAM='$PROGRAM'
export WORK='$WORK'
export UA='$UA'
export YWH='$YWH'
export RATE='$RATE'
export CURATED='$CURATED'
export SCOPE_FILE='$SCOPE_FILE'
export APEX_FILE='$APEX_FILE'
export HOSTS_FILE='$HOSTS_FILE'
export SUBS='$WORK/recon/subs_all.txt'
export INSCOPE='$WORK/recon/subs_inscope.txt'
export OOS_FILE='$OOS_FILE'
export CIDR_INSCOPE='$CIDR_IN'
export CIDR_OOS='$CIDR_OOS'
export IP_TARGETS='$IP_TARGETS'
cd "$WORK"
ENV

# pointer to the last env.sh (for a shell helper, if you use one)
printf '%s\n' "$WORK/env.sh" > "$HOME/.bb_last_env"

# --- summary --------------------------------------------------------------
echo
echo "=========================================="
echo "  PHASE 0 complete ✅"
echo "=========================================="
echo "  Folder    : $WORK"
echo "  Variables : $WORK/env.sh"
echo
echo "  UA   = $UA"
[ -n "$YWH" ] && echo "  YWH  = $YWH"
echo "  RATE = $RATE"
echo "  scope: $(wc -l < "$APEX_FILE") wildcard apex + $(wc -l < "$HOSTS_FILE") standalone hosts + $(wc -l < "$CIDR_IN") IP ranges"
[ -s "$IP_TARGETS" ] && echo "  IP ranges ready → port scan with:  ~/hunts/bb-ports.sh --ranges   (then -y)"
echo

# --- offer to run the whole pipeline now ----------------------------------
# locate bb-recon.sh (next to this script, else ~/hunts)
BBREC="$(cd "$(dirname "$0")" && pwd)/bb-recon.sh"
[ -f "$BBREC" ] || BBREC="$HOME/hunts/bb-recon.sh"
GO="$(ask 'Run the full recon now (bb-recon.sh all)? y/N' 'N')"
if printf '%s' "$GO" | grep -qiE '^y'; then
  if [ -f "$BBREC" ]; then
    # shellcheck disable=SC1090
    source "$WORK/env.sh"
    echo
    bash "$BBREC" all
  else
    echo "bb-recon.sh not found (looked next to bb-init and in ~/hunts)."
    echo "Run it yourself:  source \"$WORK/env.sh\" && ~/hunts/bb-recon.sh all"
  fi
else
  echo "  When ready:  source \"$WORK/env.sh\" && ~/hunts/bb-recon.sh all"
  echo "  Or a single stage for test/debug:  ~/hunts/bb-recon.sh <stage>"
fi
