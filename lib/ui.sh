# shellcheck shell=bash
# lib/ui.sh — the ONE output style for every kestrel command.
#
#   kestrel <cmd> · <program>          ← ui_header, once
#
#   section                            ← ui_section (dim title)
#     ✓ label       message            ← ui_ok
#     ⚠ label       message            ← ui_warn
#     ✗ label       message            ← ui_err
#     · label       message            ← ui_info  (neutral)
#     › next        kestrel ...        ← ui_next
#
# Rules: 2-space indent, labels padded to 12, colour ONLY on the marker,
# everything on stderr (stdout stays free for data), plain when not a TTY
# or when NO_COLOR is set.

if [ -t 2 ] && [ -z "${NO_COLOR:-}" ] && [ "${TERM:-}" != dumb ]; then
  _C_OK=$'\e[32m' _C_WARN=$'\e[33m' _C_ERR=$'\e[31m' _C_NEXT=$'\e[36m'
  _C_DIM=$'\e[2m' _C_BOLD=$'\e[1m' _C_OFF=$'\e[0m'
else
  _C_OK='' _C_WARN='' _C_ERR='' _C_NEXT='' _C_DIM='' _C_BOLD='' _C_OFF=''
fi

UI_WARNINGS=0
UI_ERRORS=0

# _ui_row <colour> <marker> <label> [message...]
_UI_PENDING=0
_ui_row() {
  local c="$1" m="$2" l="$3"; shift 3
  if [ "$_UI_PENDING" = 1 ]; then printf '\r\033[K' >&2; _UI_PENDING=0; fi
  if [ $# -gt 0 ]; then
    printf '  %s%s%s %-12s %s\n' "$c" "$m" "$_C_OFF" "$l" "$*" >&2
  else
    printf '  %s%s%s %s\n' "$c" "$m" "$_C_OFF" "$l" >&2
  fi
}

ui_header()  { printf '\n%skestrel %s%s%s\n\n' "$_C_BOLD" "$1" "$_C_OFF" "${2:+ · $2}" >&2; }
# ui_banner [version] — the ASCII logo, for help / version only (not every command)
ui_banner() {
  printf '\n%s%s' "$_C_NEXT" "$_C_BOLD" >&2
  cat >&2 <<'EOF'
   _                 _                  _
  | | __  ___   ___ | |_   _ __   ___  | |
  | |/ / / _ \ / __|| __| | '__| / _ \ | |
  |   < |  __/ \__ \| |_  | |   |  __/ | |
  |_|\_\ \___| |___/ \__| |_|    \___| |_|
EOF
  printf '%s  %sbug-bounty recon framework%s%s\n\n' "$_C_OFF" "$_C_DIM" "${1:+ · v$1}" "$_C_OFF" >&2
}
ui_section() { printf '\n  %s%s%s\n' "$_C_DIM" "$1" "$_C_OFF" >&2; }
ui_ok()      { _ui_row "$_C_OK"   '✓' "$@"; }
ui_warn()    { _ui_row "$_C_WARN" '⚠' "$@"; UI_WARNINGS=$((UI_WARNINGS+1)); }
ui_err()     { _ui_row "$_C_ERR"  '✗' "$@"; UI_ERRORS=$((UI_ERRORS+1)); }
ui_info()    { _ui_row "$_C_DIM"  '·' "$@"; }
ui_next()    { _ui_row "$_C_NEXT" '›' next "$@"; }
# ui_running <label> [message] — transient "in progress" line, replaced by the next row (TTY only)
ui_running() {
  [ -t 2 ] || return 0
  printf '  %s◌%s %-12s %s%s%s' "$_C_DIM" "$_C_OFF" "$1" "$_C_DIM" "${2:-running…}" "$_C_OFF" >&2
  _UI_PENDING=1
}
ui_dim()     { printf '  %s%s%s\n' "$_C_DIM" "$*" "$_C_OFF" >&2; }
ui_blank()   { printf '\n' >&2; }

# ui_die <message> [hint]  — error + optional hint, exit 1
ui_die() {
  _ui_row "$_C_ERR" '✗' "$1"
  [ -n "${2:-}" ] && ui_next "$2"
  ui_blank
  exit 1
}

# ---------------------------------------------------------------- prompts
# All prompts read from the terminal and print on stderr.

# ui_ask <question> [default]  → answer on stdout
ui_ask() {
  local q="$1" d="${2:-}" a
  printf '\n' >&2
  if [ -n "$d" ]; then
    printf '  %s?%s %s %s[%s]%s ' "$_C_NEXT" "$_C_OFF" "$q" "$_C_DIM" "$d" "$_C_OFF" >&2
  else
    printf '  %s?%s %s ' "$_C_NEXT" "$_C_OFF" "$q" >&2
  fi
  IFS= read -r a || true
  printf '%s' "${a:-$d}"
}

# ui_yesno <question> <y|n default>  → exit 0 for yes
ui_yesno() {
  local q="$1" d="${2:-n}" hint a
  [ "$d" = y ] && hint='Y/n' || hint='y/N'
  printf '\n  %s?%s %s %s[%s]%s ' "$_C_NEXT" "$_C_OFF" "$q" "$_C_DIM" "$hint" "$_C_OFF" >&2
  IFS= read -r a || true
  a="${a:-$d}"
  case "$a" in [yYsS]*) return 0 ;; *) return 1 ;; esac
}

# ui_ask_block <question>  → lines on stdout, until an empty line (paste-friendly)
ui_ask_block() {
  local line
  printf '\n  %s?%s %s\n' "$_C_NEXT" "$_C_OFF" "$1" >&2
  printf '    %s(paste or type, one per line · empty line to finish)%s\n' "$_C_DIM" "$_C_OFF" >&2
  while IFS= read -r line; do
    [ -z "${line//[[:space:]]/}" ] && break
    printf '%s\n' "$line"
  done
}

# ui_choose <question> <option>...  → chosen option text on stdout
ui_choose() {
  local q="$1"; shift
  local i=1 o a
  printf '\n  %s?%s %s\n' "$_C_NEXT" "$_C_OFF" "$q" >&2
  for o in "$@"; do printf '    %s%d%s %s\n' "$_C_DIM" "$i" "$_C_OFF" "$o" >&2; i=$((i+1)); done
  while :; do
    printf '    %s›%s ' "$_C_NEXT" "$_C_OFF" >&2
    IFS= read -r a || { printf '%s' "$1"; return; }
    if [[ "$a" =~ ^[0-9]+$ ]] && [ "$a" -ge 1 ] && [ "$a" -le $# ]; then
      eval "printf '%s' \"\${$a}\""; return
    fi
    printf '    %spick 1-%d%s\n' "$_C_WARN" $# "$_C_OFF" >&2
  done
}

# ui_elapsed <seconds> → "1h 02m" / "4m 10s" / "12s"
ui_elapsed() {
  local s="$1"
  if   [ "$s" -ge 3600 ]; then printf '%dh %02dm' $((s/3600)) $((s%3600/60))
  elif [ "$s" -ge 60 ];   then printf '%dm %02ds' $((s/60)) $((s%60))
  else printf '%ds' "$s"; fi
}
