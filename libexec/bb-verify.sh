#!/usr/bin/env bash
# bb-verify.sh — scope QA for a bb-recon run: confirms IN-scope was covered and
# OUT-of-scope was excluded. Read-only, sends NO traffic, changes nothing.
#
# It answers two authorization-critical questions:
#   1. SAFETY   — did anything out-of-scope slip into the tested assets?
#   2. COVERAGE — did every in-scope asset actually get tested?
# plus a quick DERIVATION sanity on how bb-init split the scope.
#
# Usage:
#   source ~/hunts/<prog>/env.sh && ~/hunts/bb-verify.sh
#   ~/hunts/bb-verify.sh ~/hunts/<prog>
#
# Exit code = number of problems found (0 = clean).
set -uo pipefail
# Force C locale so 'sort' and 'comm' use the same byte collation. Without this, a
# locale-aware sort and comm disagree on order → spurious "comm: input is not in sorted
# order" warnings (and, in the worst case, a wrong diff). Hostnames are ASCII, so C is safe.
export LC_ALL=C

# ---- find the program folder
WORK="${1:-${WORK:-}}"
[ -z "$WORK" ] && [ -n "${PROGRAM:-}" ] && WORK="$HOME/hunts/$PROGRAM"
if [ -z "$WORK" ] || [ ! -d "$WORK" ]; then
  echo "Program folder not found. Run:  source ~/hunts/<prog>/env.sh && ~/hunts/bb-verify.sh"
  echo "or:  ~/hunts/bb-verify.sh ~/hunts/<prog>"
  exit 2
fi
cd "$WORK"

# ---- output
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; D='\033[2m'; B='\033[1;36m'; Z='\033[0m'
BAD=0
h()    { printf "\n${B}── %s ──${Z}\n" "$1"; }
okk()  { printf "   ${G}✓${Z} %s\n" "$1"; }
bad()  { printf "   ${R}✗${Z} %s\n" "$1"; BAD=$((BAD+1)); [ -n "${2:-}" ] && printf "${D}%s${Z}\n" "$2" | sed 's/^/       /'; }
warnx(){ printf "   ${Y}⚠${Z} %s\n" "$1"; }
note() { printf "   ${D}%s${Z}\n" "$1"; }

# url/line → bare hostname (strip scheme, then trailing fields, path, port)
# handles both "https://h/p" and httpx's "https://h [200] [title]..." lines
hostof() { sed -E 's#^https?://##; s#[[:space:]].*$##; s#/.*$##; s#:.*$##'; }
have_f() { [ -s "$1" ]; }

printf "${B}bb-verify${Z} — program: %s  (%s)\n" "${PROGRAM:-$(basename "$WORK")}" "$WORK"

# ============================================================ 1. SAFETY — OOS excluded
h "1. Safety — out-of-scope must NOT appear in tested assets"
if ! have_f recon/oos.txt; then
  note "no recon/oos.txt (no out-of-scope defined) → nothing to exclude."
else
  # files that represent "things we touched / will touch"
  for pair in \
    "recon/subs_inscope.txt|enumerated in-scope subs" \
    "recon/live.txt|live hosts" \
    "recon/surface.txt|surface" \
    "recon/surface_ok.txt|surface_ok (fuzz/api/js input)" ; do
    f="${pair%%|*}"; label="${pair#*|}"
    [ -f "$f" ] || continue
    # Match against the PROBED hostname (field 1), not the whole line: httpx writes
    # live.txt with -location, so an in-scope host that 3xx-redirects to an OOS host
    # carries that OOS name in its Location column. That host was never probed as an
    # asset (the enum filter kept it out of the input), so it must not count as a leak.
    hit=$(hostof < "$f" | sort -u | grep -iFf recon/oos.txt 2>/dev/null || true)
    if [ -z "$hit" ]; then okk "no OOS in $label"
    else bad "OOS leaked into $label ($f)" "$hit"; fi
  done
  # fuzz actually ran against an OOS host? (ffuf_<host>.json named after an OOS host)
  if compgen -G "content/*.json" >/dev/null 2>&1; then
    oleak=$(ls content/*.json 2>/dev/null | sed 's#.*/ffuf_##; s#\.json$##' | grep -iFf recon/oos.txt || true)
    if [ -z "$oleak" ]; then okk "no OOS host among the fuzzed content/*.json"
    else bad "fuzz ran against OOS host(s)" "$oleak"; fi
  fi
fi

# OOS PATHS — path prefixes excluded on every host must not appear in anything we crawled/curled
if have_f recon/oos_paths.txt; then
  pre=$(sed -e 's/[][(){}.^$*+?|\\]/\\&/g' recon/oos_paths.txt | awk 'NF' | paste -sd'|' -)
  if [ -n "$pre" ]; then
    for pair in \
      "recon/robots_targets.txt|robots targets (curled in harvest)" \
      "recon/robots_checked.txt|robots checked" \
      "recon/sitemap_urls.txt|sitemap URLs" \
      "js/_urls.txt|crawled .js URLs" ; do
      f="${pair%%|*}"; label="${pair#*|}"
      [ -f "$f" ] || continue
      hit=$(grep -iE "$pre" "$f" 2>/dev/null || true)
      if [ -z "$hit" ]; then okk "no out-of-scope path in $label"
      else bad "out-of-scope path leaked into $label ($f)" "$hit"; fi
    done
  fi
fi

# ============================================================ 2. COVERAGE — in-scope tested
h "2. Coverage — in-scope must have been tested"
# 2a. standalone hosts (hosts.txt) all entered the probe list
if have_f recon/hosts.txt; then
  probe="recon/_probe_input.txt"
  if [ -f "$probe" ]; then
    miss=$(comm -23 <(hostof < recon/hosts.txt | sort -u) <(hostof < "$probe" | sort -u))
    if [ -z "$miss" ]; then okk "every standalone host entered the probe list (live input)"
    else bad "standalone hosts NOT probed" "$miss"; fi
  else
    warnx "no recon/_probe_input.txt → 'live' not run yet, can't check standalone coverage."
  fi
  # which standalone hosts came back live (info, not a failure: a dead host is legit)
  if [ -f recon/live.txt ]; then
    live_hosts=$(hostof < recon/live.txt | sort -u)
    dead=$(comm -23 <(hostof < recon/hosts.txt | sort -u) <(printf '%s\n' "$live_hosts"))
    [ -n "$dead" ] && note "standalone hosts not live (dead/!resolve, usually fine): $(printf '%s' "$dead" | tr '\n' ' ')"
  fi
else
  note "no recon/hosts.txt (wildcard-only scope) → no standalone hosts to check."
fi
# 2b. wildcard apex actually enumerated something
if have_f recon/apex.txt && [ -f recon/subs_inscope.txt ]; then
  while read -r a; do
    [ -z "$a" ] && continue
    n=$(grep -Fc ".$a" recon/subs_inscope.txt 2>/dev/null || echo 0)
    if [ "$n" -gt 0 ]; then okk "apex $a → $n in-scope subs"
    else warnx "apex $a → 0 subs (no subdomains found, or all out-of-scope?)"; fi
  done < recon/apex.txt
fi
# 2c. every surface_ok host got fuzzed (a content/ffuf_<host>.json exists)
if have_f recon/surface_ok.txt; then
  if compgen -G "content/*.json" >/dev/null 2>&1; then
    fuzzed=$(ls content/*.json 2>/dev/null | sed 's#.*/ffuf_##; s#\.json$##' | sort -u)
    miss=$(comm -23 <(hostof < recon/surface_ok.txt | sort -u) <(printf '%s\n' "$fuzzed" | sort -u))
    if [ -z "$miss" ]; then okk "every surface_ok host has a ffuf result"
    else bad "surface_ok hosts NOT fuzzed" "$miss"; fi
  else
    warnx "no content/*.json → 'fuzz' not run yet, can't check fuzz coverage."
  fi
fi

# ============================================================ 3. DERIVATION — bb-init split sanity
h "3. Derivation — how bb-init split the scope"
if [ -f recon/apex.txt ]; then
  dirty=$(grep -nE '\*|://|/' recon/apex.txt || true)
  if [ -z "$dirty" ]; then okk "apex.txt clean (no '*', no scheme, no path)"
  else bad "apex.txt has leftovers (should be bare domains)" "$dirty"; fi
fi
if [ -f recon/hosts.txt ]; then
  dirty=$(grep -nE '://|/|:' recon/hosts.txt || true)
  if [ -z "$dirty" ]; then okk "hosts.txt clean (bare hostnames, no scheme/path/port)"
  else bad "hosts.txt has scheme/path/port leftovers" "$dirty"; fi
fi
if [ -f recon/scope.txt ]; then
  sc=$(grep -cvE '^[[:space:]]*$' recon/scope.txt); ap=$( [ -f recon/apex.txt ] && wc -l < recon/apex.txt || echo 0 ); ho=$( [ -f recon/hosts.txt ] && wc -l < recon/hosts.txt || echo 0 )
  if [ "$((ap+ho))" -eq "$sc" ]; then okk "scope.txt ($sc entries) = apex ($ap) + hosts ($ho)"
  else warnx "scope.txt $sc entries but apex $ap + hosts $ho = $((ap+ho)) (dups collapsed by sort -u?)"; fi
fi

# ============================================================ VERDICT
h "Verdict"
if [ "$BAD" -eq 0 ]; then
  printf "   ${G}✓ Clean${Z} — in-scope covered, out-of-scope excluded. (⚠ lines, if any, are just info.)\n\n"
else
  printf "   ${R}✗ %s problem(s)${Z} — see the ✗ lines above. Fix before reporting anything.\n\n" "$BAD"
fi
exit "$BAD"
