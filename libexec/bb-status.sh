#!/usr/bin/env bash
# bb-status.sh — "doctor" for a bb-recon run: reads the files produced in $WORK and
# tells you at a glance what worked, where you'd get lost, and what the LEADS are.
#
# Sends NO traffic and changes nothing: read-only over the .txt/.json already created.
# It's the answer to "the script makes a thousand files, how do I know it went well?".
#
# Usage:
#   source ~/hunts/<prog>/env.sh && ~/hunts/bb-status.sh
#   ~/hunts/bb-status.sh ~/hunts/<prog>      # or pass the folder
#
# Stage legend:  ✓ done · ⚠ suspicious (empty where it shouldn't be) · ○ not run
set -uo pipefail

# ---- find the program folder
WORK="${1:-${WORK:-}}"
[ -z "$WORK" ] && [ -n "${PROGRAM:-}" ] && WORK="$HOME/hunts/$PROGRAM"
if [ -z "$WORK" ] || [ ! -d "$WORK" ]; then
  echo "Program folder not found."
  echo "Run:  source ~/hunts/<prog>/env.sh && ~/hunts/bb-status.sh"
  echo "or:   ~/hunts/bb-status.sh ~/hunts/<prog>"
  exit 2
fi
cd "$WORK"

# ---- output
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; D='\033[2m'; B='\033[1;36m'; M='\033[1;35m'; Z='\033[0m'
h()    { printf "\n${B}── %s ──${Z}\n" "$1"; }
note() { printf "   ${D}%s${Z}\n" "$1"; }
WARN=0

# line count of a file (0 if missing)
cnt() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }

# status of a stage file.  $1 file · $2 label · $3 role: core|lead
# core = empty is a problem (⚠).  lead = empty is normal (just no results).
fstat() {
  local f="$1" label="$2" role="${3:-lead}" n
  if [ ! -f "$f" ]; then printf "   ○ %-26s ${D}not run${Z}\n" "$label"; return; fi
  n=$(cnt "$f")
  if [ "$n" -gt 0 ]; then printf "   ${G}✓${Z} %-26s %s lines  ${D}%s${Z}\n" "$label" "$n" "$f"
  elif [ "$role" = core ]; then printf "   ${Y}⚠${Z} %-26s ${Y}EMPTY${Z} (suspicious)  ${D}%s${Z}\n" "$label" "$f"; WARN=$((WARN+1))
  else printf "   ${D}·${Z} %-26s empty (no results, ok)  ${D}%s${Z}\n" "$label" "$f"; fi
}

printf "${B}bb-status${Z} — program: ${M}%s${Z}  (%s)\n" "${PROGRAM:-$(basename "$WORK")}" "$WORK"

# ============================================================ FUNNEL per stage
h "Pipeline — what each stage produced"
echo " enum"
fstat recon/subs_all.txt       "  subs found"          lead
fstat recon/subs_inscope.txt   "  in scope"            lead
echo " live"
fstat recon/resolved.txt       "  resolve (dnsx)"      lead
fstat recon/live.txt           "  live hosts (baseline)" core
echo " triage"
fstat recon/surface.txt        "  surface"             core
fstat recon/browser_todo.txt   "  browser_todo (CF)"   lead
fstat recon/rescued.txt        "  rescued (404 speaks)" lead
fstat recon/discarded.txt      "  discarded"           lead
echo " catchall"
fstat recon/surface_ok.txt     "  surface_ok (200 ok)" core
fstat recon/surface_catchall.txt "  surface_catchall"  lead
echo " quickhits"
fstat recon/quickhits.txt            "  raw responses"       lead
fstat recon/quickhits_interesting.txt "  odd size"           lead
fstat recon/quickhits_auth.txt       "  401/403-gated leads" lead
echo " harvest"
fstat recon/robots_urls.txt    "  real robots.txt"     lead
fstat recon/robots_targets.txt "  targets from robots" lead
fstat recon/sitemap_urls.txt   "  URLs from sitemap"   lead
echo " fuzz"
njson=$(find content -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
if [ "$njson" -gt 0 ]; then printf "   ${G}✓${Z} %-26s %s files  ${D}content/*.json${Z}\n" "  ffuf output per host" "$njson"
else printf "   ○ %-26s ${D}not run${Z}\n" "  ffuf output per host"; fi
echo " api"
fstat recon/api_json.txt       "  JSON 200 endpoints"  lead
echo " js"
js_urls=$(cnt js/_urls.txt)
js_files=$(find js -type f -name '*.js' 2>/dev/null | wc -l | tr -d ' ')
if [ -f js/_urls.txt ]; then printf "   ${G}✓${Z} %-26s %s URLs · %s bundles downloaded  ${D}js/${Z}\n" "  js recon" "$js_urls" "$js_files"
else printf "   ○ %-26s ${D}not run${Z}\n" "  js recon"; fi

# ============================================================ FUNNEL COHERENCE
h "Funnel coherence (the numbers must narrow down)"
RES=$(cnt recon/resolved.txt); LIVE=$(cnt recon/live.txt)
SURF=$(cnt recon/surface.txt); SOK=$(cnt recon/surface_ok.txt); SCA=$(cnt recon/surface_catchall.txt)
chk() { # chk <ok|ko> <description> <detail-if-ko>
  if [ "$1" = ok ]; then printf "   ${G}✓${Z} %s\n" "$2"
  else printf "   ${Y}⚠${Z} %s  ${D}%s${Z}\n" "$2" "$3"; WARN=$((WARN+1)); fi
}
if [ "$RES" -gt 0 ] && [ "$LIVE" -gt 0 ]; then
  [ "$LIVE" -le "$RES" ] && chk ok "live hosts ($LIVE) ≤ resolve ($RES)" || chk ko "live hosts ($LIVE) > resolve ($RES)?!" "live can't exceed resolved"
fi
if [ "$LIVE" -gt 0 ] && [ "$SURF" -gt 0 ]; then
  [ "$SURF" -le "$LIVE" ] && chk ok "surface ($SURF) ≤ live hosts ($LIVE)" || chk ko "surface ($SURF) > live hosts ($LIVE)?!" "surface is a subset of live"
fi
if [ "$SURF" -gt 0 ] && [ "$SOK" -gt 0 ]; then
  [ "$SOK" -le "$SURF" ] && chk ok "surface_ok ($SOK) ≤ surface ($SURF)" || chk ko "surface_ok ($SOK) > surface ($SURF)?!" "surface_ok is a subset of surface"
  # catchall partitions surface: ok + catchall ≈ surface (rescued adds hosts to surface without a probe, tolerance)
  tot=$((SOK+SCA))
  if [ "$tot" -eq "$SURF" ]; then chk ok "surface_ok + catchall = surface ($SOK+$SCA=$SURF)"
  else chk ko "surface_ok + catchall ≠ surface ($SOK+$SCA vs $SURF)" "difference = hosts added by rescued, or catchall not re-run"; fi
fi
if [ "$SOK" -eq 0 ] && [ "$SURF" -gt 0 ]; then
  chk ko "surface_ok EMPTY but surface has $SURF hosts" "catchall not run, or all catch-all → fuzz/api/js have no input"
fi

# ============================================================ THE LEADS (what to look at)
h "Leads — open these first"
show() { # show <file> <title> <preview lines>
  local f="$1" t="$2" k="${3:-5}" n
  [ -f "$f" ] || return
  n=$(cnt "$f"); [ "$n" -eq 0 ] && return
  printf "   ${M}▸ %s${Z}  ${D}(%s, %s lines)${Z}\n" "$t" "$f" "$n"
  sed -n "1,${k}p" "$f" | sed 's/^/       /'
  [ "$n" -gt "$k" ] && note "   … +$((n-k)) more (open the file)"
}
had_lead=0
for pair in \
  "recon/api_json.txt|APIs returning JSON 200" \
  "recon/quickhits_auth.txt|401 / 403-gated (APIs asking for auth)" \
  "recon/quickhits_interesting.txt|paths with an odd size" \
  "recon/rescued.txt|root-404 hosts that 'speak' (API/auth/infra)" \
  "recon/browser_todo.txt|CF walls to open BY HAND in the browser" \
  "recon/robots_targets.txt|explicit targets from robots" ; do
  f="${pair%%|*}"; t="${pair#*|}"
  if [ -f "$f" ] && [ "$(cnt "$f")" -gt 0 ]; then had_lead=1; show "$f" "$t"; fi
done
[ "$had_lead" -eq 0 ] && note "no automatic leads in the files (normal on mature targets). Check summary and the js/ bundles by hand."

# ============================================================ TOOL ERRORS
h "Errors reported by the tools (notes/tools.log)"
if [ -f notes/tools.log ]; then
  errs=$(grep -icE '\[err\]|\bEOF\b|panic|fatal' notes/tools.log 2>/dev/null || true); errs=${errs:-0}
  if [ "$errs" -gt 0 ]; then
    printf "   ${Y}⚠${Z} %s error lines in the tools log.\n" "$errs"; WARN=$((WARN+1))
    grep -iE '\[err\]|\bEOF\b|panic|fatal' notes/tools.log 2>/dev/null | sort -u | sed -n '1,5p' | sed 's/^/       /'
    note "often = WAF/anti-bot dropping the tools on a host → move it to browser_todo.txt, don't hammer."
  else printf "   ${G}✓${Z} no obvious errors in the tools log.\n"; fi
else note "notes/tools.log absent (old run, or run before V1.1)."; fi

# ============================================================ VERDICT
h "Verdict"
if [ "$LIVE" -eq 0 ]; then
  printf "   ${R}✗ Pipeline did NOT start${Z}: no live host. Did you run 'live' (and 'enum' first if wildcard)?\n\n"; exit 1
fi
if [ "$WARN" -eq 0 ]; then
  printf "   ${G}✓ All coherent${Z} — the run looks like it went fine. Start from the Leads above.\n\n"
else
  printf "   ${Y}⚠ %s point(s) to look at${Z} (⚠ lines above). Not necessarily an error, but check.\n\n" "$WARN"
fi
