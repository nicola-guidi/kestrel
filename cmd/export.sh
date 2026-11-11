# shellcheck shell=bash
# kestrel export [program] [--burp] [--caido] — export the program's scope to the formats
# Burp Suite and Caido import, so you don't re-enter the scope by hand and the proxy stays in
# bounds exactly like kestrel. No flag = both. Output under recon/export/.
#
#   Burp  : recon/export/burp-scope.json   (Target > Scope: load / paste; host fields are regex)
#   Caido : recon/export/caido-scope.json  + caido-scope.txt (allow/deny globs to paste)
#
#   kestrel export [program] [--burp] [--caido]

cmd_export() {
  local prog="" which="" a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,10p' "$KESTREL_ROOT/cmd/export.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      --burp)   [ "$which" = caido ] && which=both || which=burp ;;
      --caido)  [ "$which" = burp ] && which=both || which=caido ;;
      -*) ui_die "unknown option '$a'" "kestrel export --help" ;;
      *) prog="$a" ;;
    esac
  done
  [ -n "$which" ] || which=both
  have python3 || ui_die "python3 is required" "kestrel doctor --install"
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header export "$prog"

  if [ -f scope ]; then scope_rebuild >/dev/null 2>&1 || true; fi
  local out_dir="$WORK/recon/export"
  local raw; raw="$(python3 "$KESTREL_ROOT/lib/export.py" "$WORK" "$prog" "$out_dir" "$which")" \
    || ui_die "export failed (empty scope?)" "kestrel scope $prog"

  local E_BURP_INCLUDE E_BURP_EXCLUDE E_BURP_FILE E_CAIDO_ALLOW E_CAIDO_DENY E_CAIDO_FILE E_CAIDO_TXT E_SKIPPED E_CAIDO_CIDR_OMITTED
  # shellcheck disable=SC2046
  eval "$(printf '%s\n' "$raw" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/E_\1=\x27\2\x27/')"

  if [ -n "${E_BURP_FILE:-}" ]; then
    ui_ok burp "${E_BURP_INCLUDE:-0} include · ${E_BURP_EXCLUDE:-0} exclude"
    ui_info "" "$E_BURP_FILE"
    ui_dim "  Burp → Target > Scope (advanced) → load this file, or paste its include/exclude rules"
  fi
  if [ -n "${E_CAIDO_FILE:-}" ]; then
    ui_ok caido "${E_CAIDO_ALLOW:-0} allow · ${E_CAIDO_DENY:-0} deny"
    ui_info "" "$E_CAIDO_FILE"
    ui_dim "  Caido → Scope → add the allow/deny patterns from $E_CAIDO_TXT"
    [ -n "${E_CAIDO_CIDR_OMITTED:-}" ] && ui_dim "  (Caido globs can't express CIDR: $E_CAIDO_CIDR_OMITTED in-scope range(s) omitted — Burp handles them)"
  fi
  [ -n "${E_SKIPPED:-}" ] && ui_warn "by hand" "IP ranges no host pattern can express: $E_SKIPPED"

  ui_blank
  ui_ok done "$out_dir/"
  ui_next "kestrel recon $prog --proxy   (route recon through the proxy)"
  ui_blank
}
