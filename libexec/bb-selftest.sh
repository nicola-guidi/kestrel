#!/usr/bin/env bash
# bb-selftest.sh — check in one shot that bb-recon.sh "works".
#
# Sends NO traffic: it does not run the network stages (enum/live/catchall/quickhits/
# harvest/fuzz/api/js). Instead it checks, OFFLINE:
#   1. syntax       bash -n (bb-recon.sh + ffuf-summary.sh) [+ shellcheck if present]
#   2. structure    every stage has its function AND its dispatcher entry;
#                   stage_all calls every pipeline stage
#   3. robustness   check/--help run without env; unknown stage → clean error;
#                   a network stage without $WORK → clear die (no set -u crash)
#   4. pure logic   triage (awk) and summary (jq) on synthetic FIXTURES → correct classification
#
# Usage:
#   ~/hunts/bb-selftest.sh                 # looks for bb-recon.sh next to itself
#   ~/hunts/bb-selftest.sh /path/bb-recon.sh
#
# Exit code = number of failed tests (0 = all good).
set -uo pipefail

# ---- locate bb-recon.sh (arg or next to this script)
HERE="$(cd "$(dirname "$0")" && pwd)"
BB="${1:-$HERE/bb-recon.sh}"
FFS="$HERE/ffuf-summary.sh"
BBINIT="$HERE/bb-init.sh"
[ -f "$BB" ] || { echo "bb-recon.sh not found: $BB (pass it as an argument)"; exit 99; }

# ---- output
G='\033[1;32m'; R='\033[1;31m'; Y='\033[1;33m'; D='\033[2m'; B='\033[1;36m'; Z='\033[0m'
PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf "  ${G}✓ PASS${Z}  %s\n" "$1"; }
fail() { FAIL=$((FAIL+1)); printf "  ${R}✗ FAIL${Z}  %s\n" "$1"; [ -n "${2:-}" ] && printf "         ${D}%s${Z}\n" "$2"; }
head() { printf "\n${B}── %s ──${Z}\n" "$1"; }

# run a command; pass if its exit code matches the expected one ($1)
expect_rc() { # expect_rc <expected_rc> <description> <command...>
  local want="$1" desc="$2"; shift 2
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -eq "$want" ]; then pass "$desc"; else fail "$desc" "expected rc=$want, got rc=$rc"; fi
}

# pass if the command's output CONTAINS the string
expect_out() { # expect_out <string> <description> <command...>
  local needle="$1" desc="$2"; shift 2
  local out
  out="$("$@" 2>&1)"
  if printf '%s' "$out" | grep -qF -- "$needle"; then pass "$desc"
  else fail "$desc" "missing from output: «$needle»"; fi
}

printf "${B}bb-selftest${Z} — target: %s\n" "$BB"

# ============================================================ 1. SYNTAX
head "1. Syntax"
expect_rc 0 "bash -n bb-recon.sh" bash -n "$BB"
if [ -f "$FFS" ]; then expect_rc 0 "bash -n ffuf-summary.sh" bash -n "$FFS"
else printf "  ${Y}· skip${Z}  ffuf-summary.sh not present\n"; fi
if [ -f "$BBINIT" ]; then expect_rc 0 "bash -n bb-init.sh" bash -n "$BBINIT"
else printf "  ${Y}· skip${Z}  bb-init.sh not present\n"; fi
if [ -f "$HERE/bb-verify.sh" ]; then expect_rc 0 "bash -n bb-verify.sh" bash -n "$HERE/bb-verify.sh"
else printf "  ${Y}· skip${Z}  bb-verify.sh not present\n"; fi
if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck -S error "$BB" >/dev/null 2>&1; then pass "shellcheck (no errors)"
  else fail "shellcheck" "run: shellcheck $BB"; fi
else printf "  ${Y}· skip${Z}  shellcheck not installed (optional)\n"; fi

# ============================================================ 2. STRUCTURE
head "2. Structure (stages ↔ dispatcher)"
STAGES="check enum live triage catchall quickhits harvest fuzz summary api js report all"
for s in $STAGES; do
  have_fn=0; have_case=0
  grep -qE "^stage_$s\(\)" "$BB" && have_fn=1
  grep -qE "^[[:space:]]*$s\)" "$BB" && have_case=1
  if [ "$have_fn" = 1 ] && [ "$have_case" = 1 ]; then pass "stage '$s' (function + dispatcher)"
  elif [ "$have_fn" = 0 ]; then fail "stage '$s'" "missing stage_$s()"
  else fail "stage '$s'" "missing the '$s)' entry in the dispatcher"; fi
done
# stage_all must call every pipeline stage
ALL_BODY="$(awk '/^stage_all\(\)/{f=1} f{print} /^}/{if(f)exit}' "$BB")"
for s in check enum live triage catchall quickhits harvest fuzz summary api js report; do
  if printf '%s' "$ALL_BODY" | grep -qE "run_stage $s(\$| )"; then pass "stage_all → $s"
  else fail "stage_all" "does not call '$s'"; fi
done
# guard: no 'read ... < <(...)' in code — curl -w has no trailing newline, so a newline-less
# read returns non-zero and under set -e aborts the stage (bit us in harvest once).
if grep -nE '^[[:space:]]*[^#]*read .*< <\(' "$BB" >/dev/null 2>&1; then
  fail "no risky 'read < <()'" "use resp=\$(...) command substitution instead"
else pass "no risky 'read < <()' under set -e"; fi
# mixed-scope: 'live' must union enum subs ($INSCOPE) with standalone hosts (hosts.txt)
LIVE_BODY="$(awk '/^stage_live\(\)/{f=1} f{print} /^}/{if(f)exit}' "$BB")"
if printf '%s' "$LIVE_BODY" | grep -q 'INSCOPE' && printf '%s' "$LIVE_BODY" | grep -q 'hosts.txt'; then
  pass "live unions enum subs + standalone hosts (mixed scope)"
else fail "live union" "stage_live should merge \$INSCOPE and recon/hosts.txt"; fi
# malformed identification header must be rejected, not passed to httpx as a broken -H
if grep -q 'case "\$YWH" in' "$BB" && grep -q 'malformed identification' "$BB"; then
  pass "malformed -H header guarded (colon-validated)"
else fail "YWH guard" "bb-recon should drop a YWH without a colon"; fi
# 0 live from non-empty input must warn loudly (not a silent 0 + cryptic triage die)
if printf '%s' "$LIVE_BODY" | grep -qi 'TOOL error'; then
  pass "live warns on 0-live-from-nonempty (likely tool error)"
else fail "0-live warn" "stage_live should warn when live==0 from a non-empty input"; fi
# dnsx rate decoupled from the target-facing RATE (public resolvers can go faster safely)
if printf '%s' "$LIVE_BODY" | grep -q 'DNS_RATE'; then pass "dnsx uses DNS_RATE (decoupled from target RATE)"
else fail "DNS_RATE" "dnsx should use \$DNS_RATE, not \$RATE"; fi
# api stage must probe the common Spring Boot Actuator / health endpoints (so an actuator that
# only the fuzz catches also lands in recon/api_json.txt). Locks the /health,/actuator/health paths.
API_BODY="$(awk '/^stage_api\(\)/{f=1} f{print} /^}/{if(f)exit}' "$BB")"
if printf '%s' "$API_BODY" | grep -q '/health' && printf '%s' "$API_BODY" | grep -q '/actuator/health'; then
  pass "api probes /health + /actuator/health (Spring Boot Actuator)"
else fail "api health paths" "stage_api APIP should include /health and /actuator/health"; fi
# run_stage must survive a stage whose LAST command returns non-zero: under set -e a failing
# subshell aborts the parent BEFORE the next command, so it must use '( ... ) || rc=$?', never
# '( ... ); rc=$?' (which killed the whole 'all' pipeline after triage when rescued.txt was empty).
RS_BODY="$(awk '/^run_stage\(\)/{f=1} f{print} /^}/{if(f)exit}' "$BB" | grep -vE '^[[:space:]]*#')"
if printf '%s' "$RS_BODY" | grep -qE '\)[[:space:]]*\|\|[[:space:]]*rc=' \
   && ! printf '%s' "$RS_BODY" | grep -qE '\);[[:space:]]*(local[[:space:]]+)?rc='; then
  pass "run_stage is set -e safe (( stage ) || rc=\$?, keeps the pipeline going)"
else fail "run_stage set -e" "use '( stage ) || rc=\$?', not '( stage ); rc=\$?'"; fi

# shared fake WORK, used here (unknown stage) and in section 4 (fixtures)
WORK="$(mktemp -d)"; export WORK
mkdir -p "$WORK/recon" "$WORK/content" "$WORK/js" "$WORK/notes"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT

# ============================================================ 3. ROBUSTNESS
head "3. Robustness (guards)"
# check and help must NOT require env
expect_rc 0 "'check' runs without env"            env -u WORK bash "$BB" check
expect_out "Checking tools" "'check' prints the tool report" env -u WORK bash "$BB" check
expect_out "bb-recon.sh —" "'--help' prints the header" env -u WORK bash "$BB" --help
# unknown stage → clear error (needs a valid $WORK, else it dies earlier on the env guard)
expect_out "unknown stage" "unknown stage → clear message" env WORK="$WORK" bash "$BB" pippo
expect_rc 1 "unknown stage → exit 1"              env WORK="$WORK" bash "$BB" pippo
# network stage without WORK → clean die, NOT a set -u/bash crash
out_noenv="$(env -u WORK bash "$BB" enum 2>&1)"; rc_noenv=$?
if [ "$rc_noenv" -ne 0 ] && printf '%s' "$out_noenv" | grep -qF '$WORK not set' \
   && ! printf '%s' "$out_noenv" | grep -qiE 'unbound variable|syntax error'; then
  pass "'enum' without env → clean die (no crash)"
else
  fail "'enum' without env" "expected die '\$WORK not set', no crash. Output: $out_noenv"
fi
# hosts-only scope: 'enum' with empty apex must SKIP (rc 0), not die (so 'all' doesn't abort)
: > "$WORK/recon/apex.txt"
out_skip="$(env WORK="$WORK" bash "$BB" enum 2>&1)"; rc_skip=$?
if [ "$rc_skip" -eq 0 ] && printf '%s' "$out_skip" | grep -qiF 'skipping enum'; then
  pass "'enum' with empty apex → skips cleanly (hosts-only scope)"
else fail "'enum' empty apex" "expected rc 0 + 'skipping enum', got rc=$rc_skip"; fi

# ============================================================ 4. PURE LOGIC (fixtures, 0 traffic)
head "4. Pure logic on fixtures"

# ---- 4a. TRIAGE: a fake live.txt that hits every branch
cat > "$WORK/recon/live.txt" <<'EOF'
https://dead.example.com [000] [failed]
https://cf.example.com [403] [Just a moment...] [Cloudflare]
https://api.example.com [404] [Not Found]
https://infra.example.com [404] [] [] [Kong]
https://blog.example.com [404] [Not Found]
https://app.example.com [200] [Home]
EOF
if env WORK="$WORK" bash "$BB" triage >/dev/null 2>&1; then
  check_in() { grep -qF "$1" "$WORK/recon/$2" 2>/dev/null; }
  # app 200 + api/infra rescued → surface
  if check_in app.example.com surface.txt && check_in api.example.com surface.txt \
     && check_in infra.example.com surface.txt; then pass "triage: 200 + speaking-404 → surface"
  else fail "triage: surface" "expected app/api/infra in surface.txt"; fi
  # cf → browser_todo
  if check_in cf.example.com browser_todo.txt; then pass "triage: CF wall → browser_todo"
  else fail "triage: browser_todo" "expected cf.example.com"; fi
  # dead + mute-404 blog → discarded
  if check_in dead.example.com discarded.txt && check_in blog.example.com discarded.txt; then
    pass "triage: 000 + mute-404 → discarded"
  else fail "triage: discarded" "expected dead + blog in discarded.txt"; fi
  # api/infra also in rescued
  if check_in api.example.com rescued.txt && check_in infra.example.com rescued.txt; then
    pass "triage: speaking-404 logged in rescued"
  else fail "triage: rescued" "expected api + infra in rescued.txt"; fi
  # app must NOT end up among the discards
  if ! check_in app.example.com discarded.txt; then pass "triage: no good host discarded"
  else fail "triage: false discard" "app.example.com ended up in discarded.txt"; fi
else
  fail "triage: execution" "the triage stage exited with an error"
fi

# ---- 4b. SUMMARY: fake ffuf json — wall (3×403 same size) + reals (200,401) + isolated 403
cat > "$WORK/content/ffuf_wall.test.json" <<'EOF'
{"results":[
 {"url":"https://wall.test/a","host":"wall.test","status":403,"length":1000,"redirectlocation":""},
 {"url":"https://wall.test/b","host":"wall.test","status":403,"length":1000,"redirectlocation":""},
 {"url":"https://wall.test/c","host":"wall.test","status":403,"length":1000,"redirectlocation":""},
 {"url":"https://wall.test/admin","host":"wall.test","status":200,"length":500,"redirectlocation":""},
 {"url":"https://wall.test/api","host":"wall.test","status":401,"length":120,"redirectlocation":""},
 {"url":"https://wall.test/odd","host":"wall.test","status":403,"length":777,"redirectlocation":""}
]}
EOF
if command -v jq >/dev/null 2>&1; then
  SUM="$(env WORK="$WORK" bash "$BB" summary 2>/dev/null)"
  # the wall: 🔴, status 403, size 1000, collapsed as "wall ×3"
  if printf '%s' "$SUM" | grep -qE '🔴.*403.*1000' && printf '%s' "$SUM" | grep -qF 'wall ×3'; then
    pass "summary: 3×403 same size → 🔴 wall ×3"
  else fail "summary: wall" "expected a 🔴 wall line, 403 size 1000, ×3"; fi
  # 200 and 401 treated as real (🟢), NEVER a wall
  if printf '%s' "$SUM" | grep -qE '🟢.*200' && printf '%s' "$SUM" | grep -qE '🟢.*401'; then
    pass "summary: 200 and 401 → 🟢 real (never a wall)"
  else fail "summary: reals" "expected 200 and 401 marked 🟢"; fi
  # the isolated 403 (size 777) is not a wall → 🟡 verify
  if printf '%s' "$SUM" | grep -qE '🟡.*403.*777'; then pass "summary: isolated 403 → 🟡 verify"
  else fail "summary: verify" "expected the 403 size 777 as 🟡 verify"; fi
  # no 200 must appear on a 🔴 wall line
  if ! printf '%s' "$SUM" | grep -F '🔴' | grep -q '200'; then pass "summary: no 200 treated as a wall"
  else fail "summary: false wall" "a 200 ended up among the walls"; fi
else
  printf "  ${Y}· skip${Z}  jq not installed → summary tests skipped\n"
fi

# ---- 4c. REPORT: renders a self-contained HTML, escapes URLs, embeds leads
# a lead with an & in the URL → must come out HTML-escaped (&amp;), never raw
printf '200 48 https://x.test/api?a=1&b=2\n' > "$WORK/recon/api_json.txt"
if env WORK="$WORK" bash "$BB" report >/dev/null 2>&1 && [ -f "$WORK/report.html" ]; then
  H="$(cat "$WORK/report.html")"
  printf '%s' "$H" | grep -qiF '<!doctype html' && pass "report: writes a self-contained report.html" \
    || fail "report: html" "report.html has no doctype"
  printf '%s' "$H" | grep -qF 'ffuf summary' && pass "report: has the ffuf summary section" \
    || fail "report: summary section" "missing 'ffuf summary'"
  printf '%s' "$H" | grep -qF 'a=1&amp;b=2' && pass "report: URLs HTML-escaped (& → &amp;)" \
    || fail "report: escaping" "the & in a URL was not escaped"
  printf '%s' "$H" | grep -qF 'x.test/api' && pass "report: embeds the leads" \
    || fail "report: leads" "the api_json lead is not in the report"
else
  fail "report: execution" "report stage failed or produced no report.html"
fi

# ---- 4d. BB-INIT: unified scope.txt → apex.txt (wildcards) + hosts.txt (standalone)
if [ -f "$BBINIT" ]; then
  IBASE="$(mktemp -d)"
  # answers: program, id-type 3, A) hosts in (3 lines + blank), hosts out (blank),
  #          B) IPs in (2 + blank), IPs out (1 + blank), rate, wordlist, don't launch
  printf '%s\n' "ut" "3" "*.example.com" "api.test.com" "https://foo.bar/a/b" "" "" \
    "10.0.0.0/16" "192.0.2.7" "" "10.0.188.0/22" "" "5" "/tmp/wl.txt" "N" \
    | BB_BASE="$IBASE" bash "$BBINIT" >/dev/null 2>&1 || true
  IW="$IBASE/ut"
  if [ -f "$IW/recon/apex.txt" ] && grep -qx 'example.com' "$IW/recon/apex.txt" \
     && ! grep -q '\*' "$IW/recon/apex.txt"; then
    pass "bb-init: *.example.com → apex.txt 'example.com' (wildcard, stripped)"
  else fail "bb-init: apex" "expected 'example.com' in apex.txt without the *."; fi
  if grep -qx 'api.test.com' "$IW/recon/hosts.txt" && grep -qx 'foo.bar' "$IW/recon/hosts.txt"; then
    pass "bb-init: standalone hosts → hosts.txt (scheme/path stripped)"
  else fail "bb-init: hosts" "expected api.test.com and foo.bar in hosts.txt"; fi
  if grep -qx '10.0.0.0/16' "$IW/recon/cidr_inscope.txt" && grep -qx '10.0.188.0/22' "$IW/recon/cidr_oos.txt" \
     && ! grep -q '^10\.' "$IW/recon/hosts.txt"; then
    pass "bb-init: IP section → cidr_inscope.txt / cidr_oos.txt (never in hosts.txt)"
  else fail "bb-init: IP section" "expected 10.0.0.0/16 in cidr_inscope.txt and 10.0.188.0/22 in cidr_oos.txt"; fi
  if [ -s "$IW/recon/ip_targets.txt" ] && ! grep -qx '10.0.188.0/22' "$IW/recon/ip_targets.txt" \
     && grep -qx '10.0.184.0/22' "$IW/recon/ip_targets.txt" && grep -qx '192.0.2.7/32' "$IW/recon/ip_targets.txt"; then
    pass "bb-init: ip_targets.txt = in-scope ranges minus the OOS range"
  else fail "bb-init: ip_targets" "OOS range not subtracted correctly from ip_targets.txt"; fi
  if grep -q "RATE='5'" "$IW/env.sh" && grep -q "CURATED='/tmp/wl.txt'" "$IW/env.sh"; then
    pass "bb-init: env.sh carries RATE + CURATED"
  else fail "bb-init: env.sh" "expected RATE and CURATED exported"; fi
  rm -rf "$IBASE"
else
  printf "  ${Y}· skip${Z}  bb-init.sh not present → init tests skipped\n"
fi

# ============================================================ SUMMARY
head "Summary"
TOT=$((PASS+FAIL))
if [ "$FAIL" -eq 0 ]; then
  printf "  ${G}ALL GOOD${Z} — %d/%d tests passed. bb-recon.sh is healthy.\n\n" "$PASS" "$TOT"
else
  printf "  ${R}%d FAILED${Z} of %d tests. Check the ✗ lines above.\n\n" "$FAIL" "$TOT"
fi
exit "$FAIL"
