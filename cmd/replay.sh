# shellcheck shell=bash
# kestrel replay [program] — re-send everything kestrel ALREADY found through an intercepting
# proxy (Burp / Caido), so the proxy's history/sitemap fills with the discovered surface without
# re-running recon. This is the "I forgot the --proxy flag" safety net: no re-enumeration, no
# fuzzing, just the URLs on disk requested once through the proxy.
#
# Sources (all already in scope — they came from kestrel's own scoped recon):
#   recon/live.txt · recon/wayback/urls.txt · js/_urls.txt · URL leads under recon/triage/
#
#   kestrel replay [program] [--proxy[=url]]

cmd_replay() {
  local prog="" proxy_want=on a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,11p' "$KESTREL_ROOT/cmd/replay.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      --proxy)    proxy_want=on ;;
      --proxy=*)  proxy_want=on; PROXY_URL="${a#--proxy=}" ;;
      -*) ui_die "unknown option '$a'" "kestrel replay --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header replay "$prog"
  tool_ok httpx || ui_die "httpx missing" "kestrel doctor --install"

  # the proxy is the whole point here: resolve + preflight (hard stop if it isn't listening)
  proxy_for_run "$proxy_want"
  [ -n "${PROXY:-}" ] || ui_die "replay needs a proxy" "kestrel replay $prog --proxy"

  # ---- gather the discovered surface from disk (URLs only), dedup
  local list; list="$(mktemp)"
  {
    [ -s recon/live.txt ]        && awk '{print $1}' recon/live.txt
    [ -s recon/wayback/urls.txt ] && cat recon/wayback/urls.txt
    [ -s js/_urls.txt ]          && awk '{print $1}' js/_urls.txt
    local f
    for f in api_open admin_panels exposed_services code_hosts fuzz_juicy wayback_interesting; do
      [ -s "recon/triage/$f.txt" ] && awk '{print $1}' "recon/triage/$f.txt"
    done
  } 2>/dev/null | grep -E '^https?://' | sort -u > "$list" || true

  local n; n="$(count_lines "$list")"
  if [ "$n" -eq 0 ]; then
    rm -f "$list"
    ui_warn empty "nothing discovered yet to replay"
    ui_next "kestrel recon $prog"
    ui_blank; return 0
  fi
  ui_info surface "$n URL(s) from recon/live, wayback, crawl and triage leads"

  # ---- headers: same identity recon uses (UA + the program's custom headers)
  local hdrs=(-H "User-Agent: $UA") _h
  if [ -n "$YWH" ]; then case "$YWH" in *:*) hdrs+=(-H "$YWH") ;; esac; fi
  if [ -s "$HEADERS_FILE" ]; then
    while IFS= read -r _h || [ -n "$_h" ]; do
      case "$_h" in *:*) [ "$_h" = "$YWH" ] || hdrs+=(-H "$_h") ;; esac
    done < "$HEADERS_FILE"
  fi

  # ---- request each URL once, through the proxy (populates Burp/Caido), gentle rate
  local t0; t0=$(date +%s)
  ui_running replay "sending $n request(s) through $PROXY (rl $RATE)…"
  httpx -l "$list" "${hdrs[@]}" -proxy "$PROXY" \
    -sc -t 20 -timeout 10 -rl "$RATE" -silent >>"$WORK/notes/tools.log" 2>&1 || true
  rm -f "$list"

  ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · $n URL(s) replayed into the proxy"
  ui_next "check the proxy's history / sitemap"
  ui_blank
}
