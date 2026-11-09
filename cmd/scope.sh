# shellcheck shell=bash
# kestrel scope [program] [--show] — view or edit a program's scope, then rebuild recon/* from it.

cmd_scope() {
  local prog="" show=0 a
  for a in "$@"; do
    case "$a" in
      -h|--help) printf 'usage: kestrel scope [program] [--show]\n\n  Opens the scope in $EDITOR, then rebuilds the files every command reads.\n  --show   print the scope without editing\n' >&2; return 0 ;;
      --show) show=1 ;;
      -*) ui_die "unknown option '$a'" "kestrel scope --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header scope "$prog"
  [ -f "$WORK/scope" ] || ui_die "no scope file (program created by bb-init?)" "kestrel new $prog --force"

  if [ "$show" -eq 1 ]; then
    sed 's/^/  /' "$WORK/scope" >&2
    ui_blank; return 0
  fi

  local before; before="$(cksum < "$WORK/scope")"
  "${EDITOR:-${VISUAL:-nano}}" "$WORK/scope" || ui_die "editor exited with an error"
  if [ "$(cksum < "$WORK/scope")" = "$before" ]; then
    ui_info scope "unchanged"; ui_blank; return 0
  fi
  scope_rebuild || ui_die "could not parse the scope file" "kestrel scope $prog"
  scope_summary
  ui_next "kestrel recon $prog --fresh   (or kestrel retest $prog)"
  ui_blank
}
