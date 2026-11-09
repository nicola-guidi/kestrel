# shellcheck shell=bash
# kestrel info [program] — reprint the onboarding summary (no traffic).

cmd_info() {
  local prog="" a
  for a in "$@"; do
    case "$a" in
      -h|--help) printf 'usage: kestrel info [program]\n\n  Shows the program settings and scope summary.\n' >&2; return 0 ;;
      -*) ui_die "unknown option '$a'" "kestrel info --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header info "$prog"
  if [ -f "$WORK/scope" ]; then scope_rebuild >/dev/null || true; fi
  program_summary
  ui_blank
  ui_next "kestrel recon $prog"
  ui_blank
}
