# shellcheck shell=bash
# kestrel new [program] — onboarding for a new bug-bounty program (ex bb-init).
#
# Asks everything ONCE; every other command reads it from here and never asks again.
#   1 name · 2 platform · 3 program URL · 4 UA suffix · 5 custom header(s)
#   6 hosts/wildcards IN · 7 hosts/wildcards/keywords OUT · 8 IP/CIDR IN · 9 IP/CIDR OUT
#   9b paths OUT (excluded on every host) · 10 wordlist · 11 rate limit · 12 program rules
#   13 port scanning allowed · 14 run recon now
#
# Writes <program>/{kestrel.conf, scope, headers.txt, notes/rules.md, env.sh, recon/*}.

cmd_new_help() {
  cat >&2 <<'EOF'
usage: kestrel new [program] [--force]

  Interactive onboarding. Paste scope blocks straight from the program page:
  kestrel extracts hosts, wildcards and IP ranges and ignores the rest.

  --force   overwrite an existing program's settings (recon results are kept)
EOF
}

cmd_new() {
  local name="" force=0 a
  for a in "$@"; do
    case "$a" in
      -h|--help) cmd_new_help; return 0 ;;
      --force)   force=1 ;;
      -*)        ui_die "unknown option '$a'" "kestrel new --help" ;;
      *)         name="$a" ;;
    esac
  done

  ui_header new "${name:-new program}"
  have python3 || ui_die "python3 is required" "kestrel doctor --install"
  ensure_workspace

  # ---------------------------------------------------------------- 1 · identity
  ui_section program
  [ -n "$name" ] || name="$(ui_ask 'Program name (folder name, e.g. acme)')"
  valid_program_name "$name" || ui_die "invalid name '$name' (letters, digits, . _ -)"
  local work; work="$(program_dir "$name")"
  if [ -f "$work/kestrel.conf" ] && [ "$force" -eq 0 ]; then
    ui_die "'$name' already exists" "kestrel scope $name   ·   kestrel new $name --force"
  fi
  ui_info workspace "$KESTREL_BASE"
  ui_info folder "$work"

  local platform url
  platform="$(ui_choose 'Platform' HackerOne Bugcrowd YesWeHack Intigriti Other)"
  if [ "$platform" = Other ]; then platform="$(ui_ask 'Platform name' 'Other')"; fi
  url="$(ui_ask 'Program page URL (optional)' '')"

  # ---------------------------------------------------------------- 2 · identification
  ui_section identification
  ui_dim "Exactly what the program asks for. Leave empty if it asks for nothing."
  local ua_suffix headers=() h
  ua_suffix="$(ui_ask 'User-Agent suffix (appended to Mozilla/5.0)' '')"
  while IFS= read -r h; do
    h="$(printf '%s' "$h" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
    case "$h" in
      *:*) headers+=("$h") ;;
      *)   ui_warn header "'$h' is not 'Name: value' — skipped (UA strings go in the suffix)" ;;
    esac
  done < <(ui_ask_block 'Custom header(s), "Name: value"')

  # ---------------------------------------------------------------- 3 · scope
  ui_section scope
  local in_hosts out_hosts in_ips out_ips out_paths skipped
  skipped="$(mktemp)"
  in_hosts="$(ui_ask_block 'Hosts & wildcards IN scope   (*.acme.com · api.acme.com)' | python3 "$KESTREL_ROOT/lib/scope.py" normalize in 2>>"$skipped")"
  out_hosts="$(ui_ask_block 'Hosts, wildcards & keywords OUT of scope   (staging · old.acme.com)' | python3 "$KESTREL_ROOT/lib/scope.py" normalize out 2>>"$skipped")"
  in_ips="$(ui_ask_block 'IPs / CIDR ranges IN scope   (203.0.113.7 · 10.0.0.0/16 · 2001:db8::/112)' | python3 "$KESTREL_ROOT/lib/scope.py" normalize in 2>>"$skipped")"
  out_ips="$(ui_ask_block 'IPs / CIDR ranges OUT of scope' | python3 "$KESTREL_ROOT/lib/scope.py" normalize in 2>>"$skipped")"
  # paths excluded on EVERY host (not hosts/IPs): kept as literal prefixes, normalized to a leading '/'
  out_paths="$(ui_ask_block 'Paths OUT of scope — excluded on EVERY host   (/arcgis/ · /internal/api/)' \
    | awk '{sub(/^[ \t]+/,""); sub(/[ \t]+$/,"")} $0=="" || $0 ~ /^#/ {next} {if(substr($0,1,1)!="/") $0="/" $0} $0!="/" && !seen[$0]++ {print}')"
  if [ -s "$skipped" ]; then
    ui_warn ignored "$(count_lines "$skipped") pasted line(s) with no host/IP:"
    sed 's/^/                   /' "$skipped" | head -n 8 >&2
  fi
  rm -f "$skipped"
  if [ -z "$in_hosts$in_ips" ]; then ui_die "empty scope: at least one host, wildcard or IP is required"; fi

  # ---------------------------------------------------------------- 4 · run settings
  ui_section settings
  local wordlist rate rules portscan proxy_default=n proxy_url=""
  wordlist="$(ui_ask 'Wordlist' "$KESTREL_ROOT/wordlists/curated.txt")"
  wordlist="${wordlist/#\~/$HOME}"
  [ -s "$wordlist" ] || ui_warn wordlist "$wordlist not found — fuzz will need it"
  while :; do
    rate="$(ui_ask 'Rate limit (requests/sec)' '5')"
    [[ "$rate" =~ ^[0-9]+$ ]] && [ "$rate" -gt 0 ] && break
    ui_warn rate "a positive number, please"
  done
  rules="$(ui_ask_block 'Program rules worth remembering (forbidden tests, limits…), optional')"
  if ui_yesno 'Port scanning allowed by the program?' n; then portscan=y; else portscan=n; fi
  if ui_yesno 'Route traffic through an intercepting proxy (Burp/Caido) by default?' n; then
    proxy_default=y
    proxy_url="$(ui_ask 'Proxy URL' 'http://127.0.0.1:8080')"
  fi

  # ---------------------------------------------------------------- write
  mkdir -p "$work"/{recon,content,js,notes}
  {
    printf '# kestrel scope — %s · edit with: kestrel scope %s\n' "$name" "$name"
    printf '[in]\n'
    [ -n "$in_hosts" ] && printf '%s\n' "$in_hosts"
    [ -n "$in_ips" ]   && printf '%s\n' "$in_ips"
    printf '[out]\n'
    [ -n "$out_hosts" ] && printf '%s\n' "$out_hosts"
    [ -n "$out_ips" ]   && printf '%s\n' "$out_ips"
    if [ -n "$out_paths" ]; then printf '[out_paths]\n'; printf '%s\n' "$out_paths"; fi
  } > "$work/scope"

  if [ ${#headers[@]} -gt 0 ]; then printf '%s\n' "${headers[@]}" > "$work/headers.txt"; else : > "$work/headers.txt"; fi

  {
    printf '# %s — program rules\n\n' "$name"
    printf -- '- platform: %s\n' "$platform"
    [ -n "$url" ] && printf -- '- page: %s\n' "$url"
    printf -- '- rate limit: %s req/s\n' "$rate"
    printf -- '- port scanning: %s\n' "$([ "$portscan" = y ] && echo allowed || echo 'NOT allowed')"
    if [ -n "$rules" ]; then printf '\n'; printf '%s\n' "$rules"; fi
  } > "$work/notes/rules.md"

  conf_write "$work/kestrel.conf" \
    PROGRAM "$name" PLATFORM "$platform" PROGRAM_URL "$url" \
    UA_SUFFIX "$ua_suffix" RATE "$rate" CURATED "$wordlist" \
    PORTSCAN_ALLOWED "$portscan" PROXY_DEFAULT "$proxy_default" PROXY_URL "$proxy_url" \
    CREATED "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  load_program "$name"
  scope_rebuild || ui_die "could not build the scope files (check $work/scope)"
  write_legacy_env "$work"

  # ---------------------------------------------------------------- summary
  program_summary
  ui_blank

  if ui_yesno 'Run the full recon now?' n; then
    ui_blank
    dispatch recon "$name"
  else
    ui_blank
    ui_next "kestrel recon $name"
    ui_blank
  fi
}

# scope_rebuild — regenerate recon/* from <program>/scope (needs load_program first)
scope_rebuild() {
  local out
  out="$(python3 "$KESTREL_ROOT/lib/scope.py" build "$WORK")" || return 1
  # shellcheck disable=SC2046
  eval "$(printf '%s\n' "$out" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/SC_\1=\x27\2\x27/')"
}

# scope_summary — print the scope lines (after scope_rebuild)
scope_summary() {
  ui_ok scope "${SC_WILDCARDS:-0} wildcard · ${SC_HOSTS:-0} host · ${SC_CIDR_IN:-0} IP range"
  ui_ok excluded "${SC_OOS:-0} host/keyword · ${SC_CIDR_OOS:-0} IP range · ${SC_OOS_PATHS:-0} path"
  if [ "${SC_CIDR_IN:-0}" -gt 0 ]; then
    ui_ok ip-targets "${SC_TARGET_RANGES:-0} range(s) · ${SC_TARGET_IPS:-0} IPs to scan"
  fi
  [ -n "${SC_SKIPPED_V6:-}" ] && ui_warn ipv6 "too large to scan, left out: $SC_SKIPPED_V6"
  return 0
}

# program_summary — the onboarding summary for the loaded program (used by new and info)
program_summary() {
  local h n=0
  ui_section summary
  ui_ok program  "$PROGRAM · ${PLATFORM:-?}${PROGRAM_URL:+ · $PROGRAM_URL}"
  ui_ok identity "UA: $UA"
  if [ -s "$HEADERS_FILE" ]; then
    while IFS= read -r h; do [ -n "$h" ] && ui_ok header "$h" && n=$((n+1)); done < "$HEADERS_FILE"
  fi
  [ "$n" -eq 0 ] && ui_info header "none"
  scope_summary
  ui_ok settings "rate $RATE req/s · port scan $([ "$PORTSCAN_ALLOWED" = y ] && echo allowed || echo 'not allowed') · proxy $([ "${PROXY_DEFAULT:-n}" = y ] && echo "${PROXY_URL:-on}" || echo off)"
  [ -s "$WORK/notes/rules.md" ] && ui_info rules "$WORK/notes/rules.md"
  ui_info folder "$WORK"
}
