# shellcheck shell=bash
# kestrel snapshot [program] — a visual preview of the live pages. Screenshots every live host
# kestrel found (headless browser via httpx -screenshot) into a gallery you can skim to see at a
# glance what each page is: login, admin panel, default page, error, real app.
#
# Only the live hosts already found (recon/live.txt) — in scope, no new hosts. Active traffic
# (it loads the pages), so it honours the program's rate and identity, and is proxy-aware.
#
#   kestrel snapshot [program] [--surface] [--proxy[=url]] [--no-proxy]
#     --surface   screenshot the wider surface (recon/surface_ok.txt) instead of just live hosts

cmd_snapshot() {
  local prog="" proxy_want=auto src=live a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,11p' "$KESTREL_ROOT/cmd/snapshot.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
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

  local srcfile=recon/live.txt
  [ "$src" = surface ] && srcfile=recon/surface_ok.txt
  [ -s "$srcfile" ] || ui_die "no ${src} hosts yet to screenshot" "kestrel recon $prog"

  local urls; urls="$(mktemp)"
  awk '{print $1}' "$srcfile" | grep -E '^https?://' | sort -u > "$urls"
  local n; n="$(count_lines "$urls")"
  if [ "$n" -eq 0 ]; then rm -f "$urls"; ui_die "no URLs to screenshot in $srcfile"; fi

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
  ui_running snapshot "screenshotting $n live page(s) with a headless browser (rl $RATE)…"
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
    ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · open $out_dir/index.html"
    ui_next "kestrel report $prog   (the gallery is linked in the report)"
  else
    ui_warn snapshot "no screenshot produced — see notes/tools.log (Chrome present? pages reachable?)"
  fi
  ui_blank
}
