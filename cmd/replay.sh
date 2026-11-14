# shellcheck shell=bash
# kestrel replay [program] — re-send what kestrel ALREADY found through an intercepting proxy
# (Burp / Caido), so the proxy's history/sitemap fills with the discovered surface without
# re-running recon. This is the "I forgot the --proxy flag" safety net: no re-enumeration, no
# fuzzing, just the URLs on disk requested once through the proxy.
#
# Only what is worth replaying: URLs on LIVE hosts (recon/live.txt), minus out-of-scope paths.
# Archived (wayback) URLs are left out by default: they are usually hundreds of thousands and
# many belong to hosts that no longer exist. Add --wayback for them (still live hosts only).
#
#   kestrel replay [program] [--wayback] [--dry-run] [--proxy[=url]]
#     --wayback   also replay the archived URLs (recon/wayback/*) of live hosts
#     --dry-run   only show what would be sent and how long it takes; send nothing

cmd_replay() {
  local prog="" proxy_want=on wayback=0 dry=0 a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,13p' "$KESTREL_ROOT/cmd/replay.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      --proxy)    proxy_want=on ;;
      --proxy=*)  proxy_want=on; PROXY_URL="${a#--proxy=}" ;;
      --wayback)  wayback=1 ;;
      --dry-run)  dry=1 ;;
      -*) ui_die "unknown option '$a'" "kestrel replay --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header replay "$prog"
  tool_ok httpx || ui_die "httpx missing" "kestrel doctor --install"
  [ -s recon/live.txt ] || ui_die "no live hosts yet to replay" "kestrel recon $prog"

  # ---- the set of LIVE hosts: only URLs on these are replayed (a dead or archived-only host would
  # just fail DNS, and recon/live.txt is already scope-filtered)
  local tmp; tmp="$(mktemp -d)"
  awk '{print $1}' recon/live.txt | sed -E 's|^https?://([^/:?#]+).*|\1|' \
    | tr 'A-Z' 'a-z' | sort -u > "$tmp/hosts"
  # keep a URL only if its host is live
  _replay_live_only() {
    awk 'NR==FNR{h[$1]; next} { u=$0; sub(/^https?:\/\//,"",u); sub(/[\/:?#].*/,"",u); if (tolower(u) in h) print $0 }' "$tmp/hosts" -
  }
  # ... and drop out-of-scope paths
  _replay_in_scope() {
    if [ -s recon/oos_paths.txt ]; then grep -viFf recon/oos_paths.txt || true; else cat; fi
  }
  # src <name> <file>… : first column of each file → URLs → live hosts only → in scope → $tmp/<name>
  _replay_src() {
    local name="$1"; shift; local f
    for f in "$@"; do [ -s "$f" ] && awk '{print $1}' "$f"; done 2>/dev/null \
      | grep -E '^https?://' | _replay_live_only | _replay_in_scope | sort -u > "$tmp/$name" || true
    [ -f "$tmp/$name" ] || : > "$tmp/$name"
  }

  _replay_src live      recon/live.txt
  _replay_src crawl     js/_urls.txt
  _replay_src leads     recon/triage/api_open.txt recon/triage/admin_panels.txt recon/triage/exposed_services.txt \
                        recon/triage/code_hosts.txt recon/triage/fuzz_juicy.txt
  if [ "$wayback" -eq 1 ]; then
    _replay_src wayback recon/wayback/urls.txt recon/triage/wayback_interesting.txt
  else
    : > "$tmp/wayback"
  fi
  # fuzz_juicy lines are "host<TAB>url": the URL is the 2nd column — take it from there too
  if [ -s recon/triage/fuzz_juicy.txt ]; then
    awk -F'\t' 'NF>=2{print $2}' recon/triage/fuzz_juicy.txt | grep -E '^https?://' \
      | _replay_live_only | _replay_in_scope >> "$tmp/leads" || true
    sort -u -o "$tmp/leads" "$tmp/leads"
  fi

  sort -u "$tmp/live" "$tmp/crawl" "$tmp/leads" "$tmp/wayback" > "$tmp/all"
  local n; n="$(count_lines "$tmp/all")"
  if [ "$n" -eq 0 ]; then
    rm -rf "$tmp"
    ui_warn empty "nothing to replay on the live hosts"
    ui_next "kestrel recon $prog"
    ui_blank; return 0
  fi

  ui_info hosts "$(count_lines "$tmp/hosts") live host(s)"
  ui_info live "$(count_lines "$tmp/live") URL(s) from recon/live"
  ui_info crawl "$(count_lines "$tmp/crawl") URL(s) from the crawl"
  ui_info leads "$(count_lines "$tmp/leads") URL(s) from triage leads"
  if [ "$wayback" -eq 1 ]; then ui_info wayback "$(count_lines "$tmp/wayback") archived URL(s) of live hosts"
  else ui_info wayback "left out (add --wayback to include archived URLs)"; fi
  local est=$(( n / (RATE > 0 ? RATE : 1) ))
  ui_info total "$n request(s) · about $(ui_elapsed "$est") at rate $RATE"

  if [ "$dry" -eq 1 ]; then
    rm -rf "$tmp"
    ui_ok dry-run "nothing sent"
    ui_next "kestrel replay $prog   (run it for real)"
    ui_blank; return 0
  fi

  # ---- the proxy is the whole point here: resolve + preflight (hard stop if it isn't listening)
  proxy_for_run "$proxy_want"
  [ -n "${PROXY:-}" ] || { rm -rf "$tmp"; ui_die "replay needs a proxy" "kestrel replay $prog --proxy"; }

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
  httpx -l "$tmp/all" "${hdrs[@]}" -proxy "$PROXY" \
    -sc -t 20 -timeout 10 -rl "$RATE" -silent >>"$WORK/notes/tools.log" 2>&1 || true
  rm -rf "$tmp"

  ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · $n URL(s) replayed into the proxy"
  ui_next "check the proxy's history / sitemap"
  ui_blank
}
