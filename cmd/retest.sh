# shellcheck shell=bash
# kestrel retest [program] [--shallow] — only what is NEW since the last scan.
# Raw data per run in recon/retest/<stamp>/ · engine output in notes/retest.log.

cmd_retest() {
  local prog="" args=() a
  for a in "$@"; do
    case "$a" in
      -h|--help) printf 'usage: kestrel retest [program] [--shallow]\n\n  New subdomains since the last scan, which are live, then the pipeline on them.\n  --shallow   stop at the new live hosts\n' >&2; return 0 ;;
      --shallow|--no-deep) args+=(--shallow) ;;
      -*) ui_die "unknown option '$a'" "kestrel retest --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header retest "$prog"
  tool_ok httpx || ui_die "httpx missing" "kestrel doctor --install"
  [ -s recon/apex.txt ] || ui_die "no wildcard in scope: nothing to re-enumerate" "kestrel recon $prog"

  if [ -s notes/runs.log ]; then
    local lr; lr="$(tail -n1 notes/runs.log | cut -d' ' -f1)"
    local days=$(( ( $(date +%s) - $(date -d "$lr" +%s 2>/dev/null || date +%s) ) / 86400 ))
    ui_info baseline "last full scan $days day(s) ago"
  fi

  local t0 rc=0; t0=$(date +%s)
  ui_running retest "enumerating and comparing…"
  {
    printf '\n===== retest · %s =====\n' "$(date '+%F %T')"
    TOOLLOG="$WORK/notes/tools.log" bash "$KESTREL_ROOT/libexec/bb-retest.sh" "${args[@]}"
  } >> notes/retest.log 2>&1 || rc=$?

  local rdir; rdir="$(find recon/retest -mindepth 1 -maxdepth 1 -type d -name '2*' 2>/dev/null | sort | tail -n1)"
  if [ -z "$rdir" ]; then ui_die "retest did not run — see notes/retest.log"; fi

  local nn nl ng first=0
  nn="$(count_lines "$rdir/new_subs.txt")"; nl="$(count_lines "$rdir/new_live.txt")"; ng="$(count_lines "$rdir/gone_subs.txt")"
  grep -q 'baseline seeded' notes/retest.log && [ ! -f recon/retest/.seeded ] && first=1
  touch recon/retest/.seeded 2>/dev/null || true

  if [ "$first" -eq 1 ]; then
    # First retest: the baseline was just seeded from the original scan. A fresh enumeration
    # always differs from it (crt.sh/subfinder vary run to run), so a big "new" count here is
    # enumeration variance, not real new assets. The reliable signal is what's NEW *and* LIVE.
    ui_ok baseline "first retest: baseline saved ($(count_lines recon/retest/baseline_subs.txt) subdomains)"
    if [ "$nl" -gt 0 ]; then ui_ok new-live "$nl new live host(s) — the ones worth looking at"
    else ui_info new-live "no new live host"; fi
    ui_info variance "$nn names differ from the first scan (enumeration variance, normal on run one)"
    ui_info next-time "from the next retest, the count reflects real changes"
  else
    if [ "$nn" -gt 0 ]; then ui_ok new "$nn new subdomain(s) · $nl live"
    else ui_info new "nothing new"; fi
    [ "$ng" -gt 0 ] && ui_info gone "$ng subdomain(s) disappeared"
  fi
  if [ -d "$rdir/deep/recon" ] && [ "$nl" -gt 0 ]; then
    local d=0 f
    for f in api_json quickhits_auth quickhits_interesting rescued browser_todo robots_targets; do
      d=$((d + $(count_lines "$rdir/deep/recon/$f.txt")))
    done
    ui_ok pipeline "ran on the $nl new live host(s) · $d lead(s)"
  fi
  [ "$rc" -ne 0 ] && ui_warn engine "finished with issues · notes/retest.log"
  ui_blank
  ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · $rdir/"
  ui_next "kestrel status $prog"
  ui_blank
  notify "kestrel retest $prog done · $rdir" 2>/dev/null || true
}
