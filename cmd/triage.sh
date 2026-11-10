# shellcheck shell=bash
# kestrel triage [program] — offline triage of the recon catch into leads.
#
#   Reads only what is already on disk (recon/, content/, js/) and sorts it into lead files
#   under recon/triage/. ZERO network: not a single request is sent. Turning a path found in a
#   JS bundle into a confirmed endpoint stays a manual, minimal-touch step.
#
#   Everything it finds also lands in the report (kestrel report), under "Triage".

cmd_triage() {
  local prog="" a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,9p' "$KESTREL_ROOT/cmd/triage.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      -*) ui_die "unknown option '$a'" "kestrel triage --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header triage "$prog"
  have python3 || ui_die "python3 is required" "kestrel doctor --install"
  [ -s recon/surface_ok.txt ] || [ -d content ] || ui_die "nothing to triage yet" "kestrel recon $prog"

  local t0; t0=$(date +%s)
  ui_running triage "parsing the catch (offline, no traffic)…"
  local out; out="$(python3 "$KESTREL_ROOT/lib/triage.py" "$WORK" 2>/dev/null)" || ui_die "triage failed"
  local T_API_OPEN T_API_GATED T_API_PATHS T_FUZZ_REAL T_FUZZ_JUICY T_JS_ENDPOINTS \
        T_JS_SECRETS T_JS_UUIDS T_JS_URLS T_PARAMS T_ROBOTS_NONSTD T_ADMIN_PANELS T_CODE_HOSTS \
        T_EXPOSED_SERVICES T_SHODAN T_CATCHALL
  eval "$(printf '%s\n' "$out" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/T_\1=\x27\2\x27/')"

  ui_section "leads (look first)"
  _tri_line ok  api-open   "${T_API_OPEN:-0}"   "open JSON 200 endpoint(s)"            recon/triage/api_open.txt
  _tri_line ok  fuzz-juicy "${T_FUZZ_JUICY:-0}" "sensitive path(s) answering 200"      recon/triage/fuzz_juicy.txt
  _tri_line ok  js-secrets "${T_JS_SECRETS:-0}" "secret-looking string(s) in JS"       recon/triage/js_secrets.txt
  _tri_line ok  admin      "${T_ADMIN_PANELS:-0}" "admin/login surface(s)"             recon/triage/admin_panels.txt
  _tri_line ok  services   "${T_EXPOSED_SERVICES:-0}" "exposed dashboard/broker(s)"    recon/triage/exposed_services.txt
  _tri_line ok  code-hosts "${T_CODE_HOSTS:-0}" "git/CI host(s)"                       recon/triage/code_hosts.txt
  _tri_line ok  shodan     "${T_SHODAN:-0}"   "IP(s) with open ports (passive Shodan)" recon/triage/shodan_ports.txt

  ui_section surface
  _tri_line info api-gated  "${T_API_GATED:-0}"  "API path(s) behind 401/403"          recon/triage/api_gated.txt
  _tri_line info api-paths  "${T_API_PATHS:-0}"  "API-looking path(s), any status"     recon/triage/api_paths.txt
  _tri_line info fuzz-real  "${T_FUZZ_REAL:-0}"  "real 200(s), walls dropped"          recon/triage/fuzz_real.txt
  _tri_line info js-paths   "${T_JS_ENDPOINTS:-0}" "path(s) mined from JS bundles"     recon/triage/js_endpoints.txt
  _tri_line info robots     "${T_ROBOTS_NONSTD:-0}" "path(s) from robots/sitemap"      recon/triage/robots_nonstd.txt
  _tri_line info js-urls    "${T_JS_URLS:-0}"    "interesting crawl URL(s)"            recon/triage/js_urls.txt
  _tri_line info params     "${T_PARAMS:-0}"     "parameter name(s) for fuzzing"       recon/triage/params.txt
  _tri_line info js-uuids   "${T_JS_UUIDS:-0}"   "real UUID(s) in JS"                  recon/triage/js_uuids.txt
  { [ "${T_JS_ENDPOINTS:-0}" -gt 0 ] || [ "${T_PARAMS:-0}" -gt 0 ]; } && \
    ui_info fuzz-lists "plain path/param wordlists to replay on other hosts · recon/triage/paths_fuzz.txt · params_fuzz.txt"
  [ "${T_CATCHALL:-0}" -gt 0 ] && ui_info catch-all "${T_CATCHALL} catch-all host(s) kept OUT of the leads"

  ui_blank
  ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · recon/triage/"
  ui_next "kestrel report $prog"
  ui_blank
}

# _tri_line <ok|info> <label> <count> <message> <file> — one row only if count > 0
_tri_line() {
  local kind="$1" label="$2" n="$3" msg="$4" file="$5"
  [ "${n:-0}" -gt 0 ] || return 0
  if [ "$kind" = ok ]; then ui_ok "$label" "$n $msg · $file"
  else ui_info "$label" "$n $msg · $file"; fi
}
