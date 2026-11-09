# shellcheck shell=bash
# kestrel report [program] [--open] — build ONE HTML page from whatever data exists.
# On demand only: no command generates it on its own. Works with any subset of
# recon / ports / secrets / retest already run. No traffic, reads files only.

cmd_report() {
  local prog="" open=0 a
  for a in "$@"; do
    case "$a" in
      -h|--help) printf 'usage: kestrel report [program] [--open]\n\n  Builds <program>/report.html from the files present (recon, ports, secrets, retest).\n  --open   open it in the browser afterwards\n' >&2; return 0 ;;
      --open) open=1 ;;
      -*) ui_die "unknown option '$a'" "kestrel report --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  have python3 || ui_die "python3 is required" "kestrel doctor --install"

  ui_header report "$prog"
  # refresh the offline triage first (no traffic) so the report's Triage section is up to date
  [ -s recon/surface_ok.txt ] || [ -d content ] && python3 "$KESTREL_ROOT/lib/triage.py" "$WORK" >/dev/null 2>&1 || true
  local out="$WORK/report.html" res
  res="$(python3 "$KESTREL_ROOT/lib/report.py" "$WORK" "$out")" || ui_die "could not build the report"
  local SECTIONS NAMES
  eval "$(printf '%s\n' "$res" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/\1=\x27\2\x27/')"
  if [ "${SECTIONS:-0}" -eq 0 ]; then
    ui_warn empty "no data yet — nothing to put in the report"
    ui_next "kestrel recon $prog"
  else
    ui_ok built "${SECTIONS} section(s): ${NAMES}"
    ui_info file "$out"
  fi
  ui_blank

  if [ "$open" -eq 1 ] && [ "${SECTIONS:-0}" -gt 0 ]; then
    if command -v xdg-open >/dev/null 2>&1; then xdg-open "$out" >/dev/null 2>&1 &
    elif command -v open >/dev/null 2>&1; then open "$out" >/dev/null 2>&1 &
    else ui_info open "open it yourself: $out"; fi
  fi
}
