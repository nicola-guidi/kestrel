# shellcheck shell=bash
# kestrel status [program] [--full] — what the last run produced, leads first. No traffic.
# kestrel verify [program] [--full] — scope QA: nothing out of scope touched. No traffic.

STATUS_LEADS=(
  "api_json|APIs returning JSON 200"
  "quickhits_auth|401/403-gated paths"
  "quickhits_interesting|paths with an odd size"
  "rescued|root-404 hosts that speak"
  "browser_todo|walls to open by hand"
  "robots_targets|targets from robots.txt"
)

cmd_status() {
  local prog="" full=0 a
  for a in "$@"; do
    case "$a" in
      -h|--help) printf 'usage: kestrel status [program] [--full]\n\n  --full   stage-by-stage detail with lead previews\n' >&2; return 0 ;;
      --full) full=1 ;;
      -*) ui_die "unknown option '$a'" "kestrel status --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"

  if [ "$full" -eq 1 ]; then
    bash "$KESTREL_ROOT/libexec/bb-status.sh"; return
  fi

  local last="never"
  [ -s notes/runs.log ] && last="$(tail -n1 notes/runs.log | cut -d' ' -f1 | tr T ' ' | cut -c1-16) UTC"
  ui_header status "$prog"
  ui_info program "${PLATFORM:-?} · last full run: $last"

  if [ ! -s recon/live.txt ]; then
    ui_blank; ui_warn recon "no results yet"; ui_next "kestrel recon $prog"; ui_blank; return 0
  fi

  # funnel: the numbers must narrow down
  ui_section funnel
  ui_info hosts "$(count_lines recon/subs_inscope.txt) in scope › $(count_lines recon/resolved.txt) resolving › $(count_lines recon/live.txt) live › $(count_lines recon/surface.txt) surface › $(count_lines recon/surface_ok.txt) real"

  # checks: only what needs attention, plus the verify verdict
  ui_section checks
  local n=0
  bash "$KESTREL_ROOT/libexec/bb-verify.sh" > notes/verify.log 2>&1 || n=$?
  if [ "$n" -eq 0 ]; then ui_ok verify "nothing out of scope touched"
  else ui_err verify "$n problem(s) — kestrel verify $prog"; fi
  if [ -f notes/tools.log ]; then
    local errs; errs=$(grep -ciE '\[err\]|\bEOF\b|panic|fatal' notes/tools.log 2>/dev/null || true)
    [ "${errs:-0}" -gt 0 ] && ui_warn tools "$errs error lines in notes/tools.log (often a WAF dropping the tools)"
  fi
  [ -s recon/ports/shodan.txt ] && ui_ok shodan "$(count_lines recon/ports/shodan.txt) IPs with known open ports · recon/ports/shodan.txt"
  [ -s recon/secrets/th_all.jsonl ] && ui_warn secrets "$(count_lines recon/secrets/th_all.jsonl) verified secret(s) · kestrel secrets $prog"

  # leads: count + file, nothing else
  ui_section leads
  local pair f t c any=0
  for pair in "${STATUS_LEADS[@]}"; do
    f="recon/${pair%%|*}.txt"; t="${pair#*|}"; c="$(count_lines "$f")"
    [ "$c" -gt 0 ] || continue
    printf '  %s›%s %-4s %-30s %s%s%s\n' "$_C_NEXT" "$_C_OFF" "$c" "$t" "$_C_DIM" "$f" "$_C_OFF" >&2
    any=1
  done
  [ "$any" -eq 0 ] && ui_info leads "no automatic leads — look at the JS bundles in js/"

  ui_blank
  [ -f report.html ] && ui_info report "$WORK/report.html"
  ui_next "kestrel status $prog --full"
  ui_blank
}

cmd_verify() {
  local prog="" full=0 a
  for a in "$@"; do
    case "$a" in
      -h|--help) printf 'usage: kestrel verify [program] [--full]\n\n  Safety: nothing out of scope touched. Coverage: every in-scope asset tested.\n' >&2; return 0 ;;
      --full) full=1 ;;
      -*) ui_die "unknown option '$a'" "kestrel verify --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  if [ "$full" -eq 1 ]; then bash "$KESTREL_ROOT/libexec/bb-verify.sh"; return; fi

  ui_header verify "$prog"
  local n=0
  bash "$KESTREL_ROOT/libexec/bb-verify.sh" > notes/verify.log 2>&1 || n=$?
  # keep only the engine's ✗/⚠ lines, without colours and indentation
  local issues
  issues="$(sed 's/\x1b\[[0-9;]*m//g' notes/verify.log | grep -E '^[[:space:]]*(✗|⚠)' | sed 's/^[[:space:]]*//' | head -n 8 || true)"
  if [ "$n" -eq 0 ]; then
    ui_ok safety "nothing out of scope touched"
    ui_ok coverage "in-scope assets covered"
  else
    ui_err verify "$n problem(s)"
  fi
  if [ -n "$issues" ]; then
    local l
    while IFS= read -r l; do
      case "$l" in ✗*) ui_err detail "${l#✗ }" ;; *) ui_info note "${l#⚠ }" ;; esac
    done <<< "$issues"
  fi
  ui_blank
  ui_next "kestrel verify $prog --full   (details: notes/verify.log)"
  ui_blank
  [ "$n" -eq 0 ]
}
