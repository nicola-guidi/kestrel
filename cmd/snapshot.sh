# shellcheck shell=bash
# kestrel snapshot [program] — a visual preview of the pages that matter. An EXTRA, not a pipeline
# stage: it screenshots pages (headless browser via httpx -screenshot) into a gallery you can skim
# to see at a glance what each page is — login, admin panel, default page, error, real app. Run it
# whenever you want "a bit more info"; it feeds nothing else (not the report, not triage, not the
# db) and nothing depends on it.
#
# By default it shoots only the TRIAGE LEADS — the pages triage already flagged as interesting
# (admin panels, open APIs, exposed services, juicy fuzz hits, odd robots entries, interesting
# wayback URLs) — so you get a handful of pages that count, not thousands. Use --live to screenshot
# every live host instead.
#
# In scope only (the URLs come from kestrel's own scoped recon/triage). Active traffic (it loads the
# pages), so it honours the program's rate and identity, and is proxy-aware.
#
#   kestrel snapshot [program] [--live] [--surface] [--proxy[=url]] [--no-proxy]
#     --live      screenshot every live host (recon/live.txt) instead of just the triage leads
#     --surface   screenshot the wider surface (recon/surface_ok.txt) instead

cmd_snapshot() {
  local prog="" proxy_want=auto src=leads a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,17p' "$KESTREL_ROOT/cmd/snapshot.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      --live)     src=live ;;
      --surface)  src=surface ;;
      --proxy)    proxy_want=on ;;
      --proxy=*)  proxy_want=on; PROXY_URL="${a#--proxy=}" ;;
      --no-proxy) proxy_want=off ;;
      -*) ui_die "unknown option '$a'" "kestrel snapshot --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header snapshot "$prog"
  tool_ok httpx || ui_die "httpx missing" "kestrel doctor --install"
  have python3 || ui_die "python3 is required" "kestrel doctor --install"

  # ---- gather the URLs to screenshot, by source, dedup
  local urls; urls="$(mktemp)"
  case "$src" in
    leads)
      # the pages triage flagged as worth a look — on-target HTTP endpoints only
      local f
      for f in admin_panels api_open exposed_services fuzz_juicy robots_nonstd wayback_interesting; do
        [ -s "recon/triage/$f.txt" ] && awk '{print $1}' "recon/triage/$f.txt"
      done 2>/dev/null | grep -E '^https?://' | sort -u > "$urls" || true
      if [ ! -s "$urls" ]; then
        rm -f "$urls"
        ui_warn empty "no triage leads yet to screenshot"
        ui_next "kestrel triage $prog   (or shoot every live host: kestrel snapshot $prog --live)"
        ui_blank; return 0
      fi ;;
    live)
      [ -s recon/live.txt ] || ui_die "no live hosts yet to screenshot" "kestrel recon $prog"
      awk '{print $1}' recon/live.txt | grep -E '^https?://' | sort -u > "$urls" ;;
    surface)
      [ -s recon/surface_ok.txt ] || ui_die "no surface yet to screenshot" "kestrel recon $prog"
      awk '{print $1}' recon/surface_ok.txt | grep -E '^https?://' | sort -u > "$urls" ;;
  esac
  local n; n="$(count_lines "$urls")"
  if [ "$n" -eq 0 ]; then rm -f "$urls"; ui_die "no URLs to screenshot"; fi
  case "$src" in
    leads)   ui_info source "$n triage lead(s) — the pages worth a look (use --live for every host)" ;;
    live)    ui_info source "$n live host(s)" ;;
    surface) ui_info source "$n surface URL(s)" ;;
  esac

  # a local Chrome makes httpx reuse it instead of downloading its own copy
  local chrome; chrome="$(chrome_bin)"
  local chrome_flag=()
  if [ -n "$chrome" ]; then chrome_flag=(-system-chrome); ui_info chrome "$chrome"
  else ui_warn chrome "no local Chrome/Chromium — httpx will fetch its own headless build (install chromium for speed)"; fi

  proxy_for_run "$proxy_want"

  # headers: same identity as recon (UA + the program's custom headers)
  local hdrs=(-H "User-Agent: $UA") _h
  if [ -n "$YWH" ]; then case "$YWH" in *:*) hdrs+=(-H "$YWH") ;; esac; fi
  if [ -s "$HEADERS_FILE" ]; then
    while IFS= read -r _h || [ -n "$_h" ]; do
      case "$_h" in *:*) [ "$_h" = "$YWH" ] || hdrs+=(-H "$_h") ;; esac
    done < "$HEADERS_FILE"
  fi
  local px=(); [ -n "${PROXY:-}" ] && px=(-proxy "$PROXY")

  local out_dir="recon/snapshots"; mkdir -p "$out_dir"
  local t0; t0=$(date +%s)
  ui_running snapshot "screenshotting $n page(s) with a headless browser (rl $RATE)…"
  # -ss screenshot · -esb keep the PNGs out of the JSON · -srd stores responses+screenshots ·
  # -json/-o gives us url+status+title+path to build the gallery · rate from the program
  httpx -l "$urls" "${hdrs[@]}" ${px[@]+"${px[@]}"} "${chrome_flag[@]}" \
    -ss -esb -srd "$out_dir" \
    -sc -title -json -o "$out_dir/httpx.jsonl" \
    -t 10 -timeout 20 -rl "$RATE" -silent >>"$WORK/notes/tools.log" 2>&1 || true
  rm -f "$urls"

  # build the gallery (index.html) from the JSONL, or from the PNGs on disk as a fallback
  local g; g="$(python3 "$KESTREL_ROOT/lib/gallery.py" "$out_dir" "$prog" 2>>"$WORK/notes/tools.log")" || true
  local SN_SHOTS SN_INDEX
  eval "$(printf '%s\n' "$g" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/SN_\1=\x27\2\x27/')"

  ui_blank
  if [ "${SN_SHOTS:-0}" -gt 0 ]; then
    ui_ok snapshot "${SN_SHOTS} screenshot(s) · $out_dir/index.html"
    ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · open $out_dir/index.html in a browser"
  else
    ui_warn snapshot "no screenshot produced — see notes/tools.log (Chrome present? pages reachable?)"
  fi
  ui_blank
}
