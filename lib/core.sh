# shellcheck shell=bash
# lib/core.sh — paths, global config, program loading. Sourced by the dispatcher.

KESTREL_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/kestrel"
KESTREL_CONFIG="$KESTREL_CONFIG_DIR/config"
KESTREL_LAST="$KESTREL_CONFIG_DIR/last_program"
DEFAULT_UA='Mozilla/5.0'
DEFAULT_WORKSPACE="$HOME/hunts"

# Workspace = the folder where programs live. Precedence:
#   1. KESTREL_BASE in the environment (one-off override)
#   2. KESTREL_WORKSPACE saved in ~/.config/kestrel/config (chosen once, on first use)
#   3. ~/hunts
_env_base="${KESTREL_BASE:-}"
# global config (optional): workspace, notification settings
# shellcheck disable=SC1090
[ -f "$KESTREL_CONFIG" ] && . "$KESTREL_CONFIG"
KESTREL_BASE="${_env_base:-${KESTREL_WORKSPACE:-$DEFAULT_WORKSPACE}}"
unset _env_base

# global_set KEY VALUE — persist a key in ~/.config/kestrel/config
global_set() {
  mkdir -p "$KESTREL_CONFIG_DIR"
  [ -f "$KESTREL_CONFIG" ] || printf '# kestrel global config\n' > "$KESTREL_CONFIG"
  conf_set "$KESTREL_CONFIG" "$1" "$2"
}

# ensure_workspace — first use: ask once where programs live, create it, remember it
ensure_workspace() {
  if ! grep -q '^KESTREL_WORKSPACE=' "$KESTREL_CONFIG" 2>/dev/null; then
    local w
    ui_section workspace
    ui_dim "First run: where should kestrel keep your programs?"
    w="$(ui_ask 'Workspace folder' "$KESTREL_BASE")"
    w="${w/#\~/$HOME}"
    KESTREL_BASE="$w"
    global_set KESTREL_WORKSPACE "$w"
  fi
  mkdir -p "$KESTREL_BASE" 2>/dev/null || ui_die "cannot create workspace $KESTREL_BASE"
  [ -w "$KESTREL_BASE" ] || ui_die "workspace $KESTREL_BASE is not writable"
}

# valid program name: letters, digits, dot, dash, underscore
valid_program_name() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; }

program_dir() { printf '%s/%s' "$KESTREL_BASE" "$1"; }

# list program names (folders that hold a kestrel.conf or a legacy env.sh)
list_programs() {
  local d
  [ -d "$KESTREL_BASE" ] || return 0
  for d in "$KESTREL_BASE"/*/; do
    [ -f "$d/kestrel.conf" ] || [ -f "$d/env.sh" ] || continue
    basename "$d"
  done
}

remember_program() { mkdir -p "$KESTREL_CONFIG_DIR" && printf '%s\n' "$1" > "$KESTREL_LAST"; }

# resolve_program [name] → prints the program name, or dies with a hint.
# No name given: the last program used, or the only one that exists.
resolve_program() {
  local p="${1:-}" all n
  if [ -z "$p" ]; then
    if [ -s "$KESTREL_LAST" ]; then p="$(cat "$KESTREL_LAST")"
    else
      all="$(list_programs)"; n=$(printf '%s' "$all" | grep -c . || true)
      [ "$n" -eq 1 ] && p="$all"
    fi
  fi
  [ -n "$p" ] || ui_die "no program given" "kestrel ls   ·   kestrel new <program>"
  [ -d "$(program_dir "$p")" ] || ui_die "program '$p' not found in $KESTREL_BASE" "kestrel new $p"
  printf '%s' "$p"
}

# write a key=value config with safe shell quoting
# conf_write <file> KEY VALUE [KEY VALUE ...]
conf_write() {
  local f="$1"; shift
  {
    printf '# kestrel program config — written by kestrel, edit with care\n'
    while [ $# -ge 2 ]; do printf '%s=%q\n' "$1" "$2"; shift 2; done
  } > "$f"
}

# conf_set <file> KEY VALUE — replace or append a single key
conf_set() {
  local f="$1" k="$2" v tmp
  v="$(printf '%q' "$3")"
  tmp="$(mktemp)"
  grep -v "^$k=" "$f" > "$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$k" "$v" >> "$tmp"
  mv "$tmp" "$f"
}

# load_program <name>: export everything the engine scripts expect (same names as
# the legacy env.sh), then cd into the program folder.
load_program() {
  PROGRAM="$1"
  WORK="$(program_dir "$PROGRAM")"
  if [ -f "$WORK/kestrel.conf" ]; then
    # shellcheck disable=SC1091
    . "$WORK/kestrel.conf"
  elif [ -f "$WORK/env.sh" ]; then
    # legacy program created by bb-init: still usable
    # shellcheck disable=SC1091
    . "$WORK/env.sh"
    LEGACY_PROGRAM=1
  else
    ui_die "'$PROGRAM' has no kestrel.conf" "kestrel new $PROGRAM"
  fi
  UA="${UA:-$DEFAULT_UA${UA_SUFFIX:+ $UA_SUFFIX}}"
  RATE="${RATE:-5}"
  CURATED="${CURATED:-$KESTREL_ROOT/wordlists/curated.txt}"
  HEADERS_FILE="$WORK/headers.txt"
  # legacy single header: the first custom header (engine scripts also read HEADERS_FILE)
  YWH="${YWH:-}"
  if [ -z "$YWH" ] && [ -s "$HEADERS_FILE" ]; then YWH="$(head -n1 "$HEADERS_FILE")"; fi
  export PROGRAM WORK UA YWH RATE CURATED HEADERS_FILE
  export PLATFORM="${PLATFORM:-}" PROGRAM_URL="${PROGRAM_URL:-}" PORTSCAN_ALLOWED="${PORTSCAN_ALLOWED:-n}"
  # intercepting-proxy settings (Burp/Caido): the URL lives in PROXY_URL and the on/off
  # preference in PROXY_DEFAULT. The engine-facing PROXY var is set ONLY by the command that
  # runs a stage (recon/retest/replay), so a URL sitting in the config never proxies by itself.
  export PROXY_URL="${PROXY_URL:-}" PROXY_DEFAULT="${PROXY_DEFAULT:-n}"
  export SCOPE_FILE="$WORK/recon/scope.txt"
  export APEX_FILE="$WORK/recon/apex.txt"
  export HOSTS_FILE="$WORK/recon/hosts.txt"
  export SUBS="$WORK/recon/subs_all.txt"
  export INSCOPE="$WORK/recon/subs_inscope.txt"
  export OOS_FILE="$WORK/recon/oos.txt"
  export CIDR_INSCOPE="$WORK/recon/cidr_inscope.txt"
  export CIDR_OOS="$WORK/recon/cidr_oos.txt"
  export IP_TARGETS="$WORK/recon/ip_targets.txt"
  cd "$WORK" || ui_die "cannot enter $WORK"
  remember_program "$PROGRAM"
}

# write the legacy env.sh so the original bb-* scripts keep working on this program
write_legacy_env() {
  local w="$1"
  {
    printf '# Session variables for: %s  (generated by kestrel — kestrel loads these itself)\n' "$PROGRAM"
    printf 'export %s=%q\n' \
      PROGRAM "$PROGRAM" WORK "$w" UA "$UA" YWH "$YWH" RATE "$RATE" CURATED "$CURATED" \
      SCOPE_FILE "$w/recon/scope.txt" APEX_FILE "$w/recon/apex.txt" HOSTS_FILE "$w/recon/hosts.txt" \
      SUBS "$w/recon/subs_all.txt" INSCOPE "$w/recon/subs_inscope.txt" OOS_FILE "$w/recon/oos.txt" \
      CIDR_INSCOPE "$w/recon/cidr_inscope.txt" CIDR_OOS "$w/recon/cidr_oos.txt" \
      IP_TARGETS "$w/recon/ip_targets.txt" HEADERS_FILE "$w/headers.txt"
    printf 'cd %q\n' "$w"
  } > "$w/env.sh"
}

# have <tool> — is it on PATH
have() { command -v "$1" >/dev/null 2>&1; }

# ---- intercepting proxy (Burp / Caido) ------------------------------------
# proxy_default_url — the proxy configured for this program (PROXY_URL in kestrel.conf),
# else the conventional Burp/Caido default on localhost:8080.
proxy_default_url() { printf '%s' "${PROXY_URL:-http://127.0.0.1:8080}"; }

# resolve_proxy on|off|auto — echo the proxy URL to use (empty = don't proxy).
#   on   : the configured/default URL        (a --proxy flag)
#   off  : nothing                            (a --no-proxy flag)
#   auto : the URL iff PROXY_DEFAULT=y        (the program's onboarding choice)
resolve_proxy() {
  case "${1:-auto}" in
    on)   proxy_default_url ;;
    off)  : ;;
    auto) [ "${PROXY_DEFAULT:-n}" = y ] && proxy_default_url || : ;;
  esac
}

# proxy_for_run on|off|auto — set and export the engine-facing PROXY for this run.
# Resolves the URL, preflights it (hard stop if nothing is listening — never fire a whole run at
# a dead proxy), and prints the one-line notice. Call once in a command before running a stage.
# Not in a subshell: ui_die must stop the command, not just a $(...) child.
proxy_for_run() {
  PROXY="$(resolve_proxy "${1:-auto}")"
  if [ -n "$PROXY" ]; then
    proxy_up "$PROXY" || ui_die "proxy not listening at $PROXY" "start Burp/Caido, or re-run with --no-proxy"
    ui_info proxy "routing target traffic through $PROXY"
  fi
  export PROXY
}

# proxy_up <url|host:port> — true if something is listening there (TCP connect, no deps).
# Used as a preflight so kestrel never fires a whole run at a proxy that isn't running.
proxy_up() {
  local hp="${1#*://}"; hp="${hp%%/*}"
  local host="${hp%%:*}" port="${hp##*:}"
  [ "$host" = "$port" ] && port=8080
  [ -n "$host" ] || host=127.0.0.1
  if have timeout; then
    timeout 2 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
  else
    (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null
  fi
}

# count lines of a file (0 if missing)
count_lines() { [ -f "$1" ] && wc -l < "$1" | tr -d ' ' || echo 0; }
