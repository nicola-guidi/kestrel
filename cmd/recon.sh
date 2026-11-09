# shellcheck shell=bash
# kestrel recon [program] [stage] [--fresh] [--from <stage>] [--skip a,b]
#
# Runs the recon pipeline stage by stage. On screen: ONE line per stage with the numbers.
# Everything else (per-host rows, tool output) goes to notes/recon.log and the report.
#
# Resumes automatically: if a run was interrupted, the next 'kestrel recon' continues
# from the first stage not completed. --fresh starts over.
# At the end: scope verify + a short status, then the report path.

RECON_STAGES=(enum live triage catchall quickhits harvest fuzz summary api js)

cmd_recon_help() {
  cat >&2 <<'EOF'
usage: kestrel recon [program] [stage] [options]

  (no stage)        full pipeline, resuming an interrupted run
  <stage>           run a single stage: enum live triage catchall quickhits
                    harvest fuzz summary api js report
  --fresh           ignore an interrupted run, start over
  --from <stage>    start from this stage
  --skip a,b        skip these stages

  Details of every stage: notes/recon.log · tools output: notes/tools.log
EOF
}

# recon_line <stage> → the one-line result of a stage, from the files it produced
recon_line() {
  local c=count_lines
  case "$1" in
    enum)      printf '%s subdomains · %s in scope' "$($c recon/subs_all.txt)" "$($c recon/subs_inscope.txt)" ;;
    live)      printf '%s resolving · %s live' "$($c recon/resolved.txt)" "$($c recon/live.txt)" ;;
    triage)    printf '%s surface · %s browser-only · %s discarded' "$($c recon/surface.txt)" "$($c recon/browser_todo.txt)" "$($c recon/discarded.txt)" ;;
    catchall)  printf '%s real · %s catch-all' "$($c recon/surface_ok.txt)" "$($c recon/surface_catchall.txt)" ;;
    quickhits) printf '%s hits · %s auth-gated · %s odd size' "$($c recon/quickhits.txt)" "$($c recon/quickhits_auth.txt)" "$($c recon/quickhits_interesting.txt)" ;;
    harvest)   printf '%s robots targets · %s sitemap URLs' "$($c recon/robots_targets.txt)" "$($c recon/sitemap_urls.txt)" ;;
    fuzz)      printf '%s hosts fuzzed' "$(find content -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')" ;;
    summary)   printf 'leads ranked' ;;
    api)       printf '%s JSON endpoints' "$($c recon/api_json.txt)" ;;
    js)        printf '%s JS URLs · %s bundles' "$($c js/_urls.txt)" "$(find js -type f -name '*.js' 2>/dev/null | wc -l | tr -d ' ')" ;;
    report)    printf 'report.html' ;;
  esac
}

# a stage whose main output is empty when it shouldn't be → warning
recon_suspicious() {
  case "$1" in
    live)     [ "$(count_lines recon/live.txt)" -eq 0 ] ;;
    triage)   [ "$(count_lines recon/live.txt)" -gt 0 ] && [ "$(count_lines recon/surface.txt)" -eq 0 ] ;;
    *)        return 1 ;;
  esac
}

cmd_recon() {
  local prog="" only="" from="" skip="" fresh=0
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) cmd_recon_help; return 0 ;;
      --fresh)   fresh=1 ;;
      --from)    from="${2:-}"; shift ;;
      --skip)    skip="${2:-}"; shift ;;
      -*)        ui_die "unknown option '$1'" "kestrel recon --help" ;;
      *)
        if [[ " ${RECON_STAGES[*]} all " == *" $1 "* ]]; then only="$1"
        elif [ -z "$prog" ]; then prog="$1"
        else ui_die "unknown stage '$1'" "kestrel recon --help"; fi ;;
    esac
    shift
  done
  [ "$only" = all ] && only=""
  [ -n "$from" ] && [[ " ${RECON_STAGES[*]} " != *" $from "* ]] && ui_die "unknown stage '$from'"

  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header recon "$prog"

  # ---------------------------------------------------------------- pre-flight
  local t miss=()
  for t in curl jq httpx; do tool_ok "$t" || miss+=("$t"); done
  [ ${#miss[@]} -eq 0 ] || ui_die "missing: ${miss[*]}" "kestrel doctor --install"
  [ -s recon/apex.txt ] && ! tool_ok subfinder && ui_warn enum "subfinder missing: only crt.sh will be used"
  if [ -f scope ]; then scope_rebuild >/dev/null 2>&1 || true; fi
  ui_info scope "$(count_lines recon/apex.txt) wildcard · $(count_lines recon/hosts.txt) host · $(count_lines recon/oos.txt) excluded"
  ui_info identity "$UA$([ -s "$HEADERS_FILE" ] && printf ' · %s header(s)' "$(count_lines "$HEADERS_FILE")")"
  ui_info rate "$RATE req/s"
  if [ -f notes/rules.md ]; then
    local r; r="$(grep -v -e '^#' -e '^- ' notes/rules.md | sed '/^[[:space:]]*$/d' | head -n 3)"
    [ -n "$r" ] && while IFS= read -r t; do ui_info rules "$t"; done <<< "$r"
  fi

  # ---------------------------------------------------------------- plan
  local state=notes/recon.state stages=() s
  if [ -n "$only" ]; then
    stages=("$only")
  else
    if [ "$fresh" -eq 1 ]; then rm -f "$state"; fi
    local started=0
    for s in "${RECON_STAGES[@]}"; do
      [ -n "$from" ] && [ "$s" = "$from" ] && started=1
      [ -n "$from" ] && [ "$started" -eq 0 ] && continue
      [[ ",$skip," == *",$s,"* ]] && continue
      stages+=("$s")
    done
    if [ -s "$state" ] && [ -z "$from" ]; then
      ui_warn resume "interrupted run found: continuing (--fresh to start over)"
    else
      : > "$state"; : > notes/tools.log; : > notes/recon.log
    fi
  fi

  # ---------------------------------------------------------------- run
  ui_section pipeline
  local t0 ts rc dur
  t0=$(date +%s)
  for s in "${stages[@]}"; do
    if [ -z "$only" ] && grep -qx "$s" "$state" 2>/dev/null; then
      ui_info "$s" "done earlier · $(recon_line "$s")"; continue
    fi
    ui_running "$s"
    ts=$(date +%s); rc=0
    {
      printf '\n===== %s · %s =====\n' "$s" "$(date '+%F %T')"
      TOOLLOG="$WORK/notes/tools.log" bash "$KESTREL_ROOT/libexec/bb-recon.sh" "$s"
    } >> notes/recon.log 2>&1 || rc=$?
    dur="$(ui_elapsed $(( $(date +%s) - ts )))"
    if [ "$rc" -ne 0 ]; then
      ui_warn "$s" "$(recon_line "$s") · issues (notes/recon.log) · $dur"
    elif recon_suspicious "$s"; then
      ui_warn "$s" "$(recon_line "$s") · $dur"
    else
      ui_ok "$s" "$(recon_line "$s") · $dur"
    fi
    [ -z "$only" ] && printf '%s\n' "$s" >> "$state"
    # nothing alive → the rest of the pipeline has no input: stop cleanly
    if [ -z "$only" ] && [ "$s" = live ] && [ "$(count_lines recon/live.txt)" -eq 0 ]; then
      ui_err stopped "no live host: nothing for the next stages (see notes/tools.log)"
      rm -f "$state"; ui_blank; return 1
    fi
  done

  if [ -n "$only" ]; then ui_blank; ui_next "kestrel status $prog"; ui_blank; return 0; fi

  local total=$(( $(date +%s) - t0 ))
  printf '%s %ss %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$total" "${#stages[@]}" >> notes/runs.log
  rm -f "$state"

  # ---------------------------------------------------------------- after the run
  ui_section checks
  recon_verify_line
  recon_leads_line
  ui_blank
  ui_ok done "$(ui_elapsed "$total")"
  ui_next "kestrel status $prog   ·   kestrel report $prog"
  ui_blank
  notify "kestrel recon $prog done in $(ui_elapsed "$total") · $(recon_leads_count) leads" 2>/dev/null || true
}

# verify in one line (exit code of the engine = number of problems)
recon_verify_line() {
  local n=0
  bash "$KESTREL_ROOT/libexec/bb-verify.sh" > notes/verify.log 2>&1 || n=$?
  if [ "$n" -eq 0 ]; then ui_ok verify "nothing out of scope touched · in-scope covered"
  else ui_err verify "$n problem(s) · notes/verify.log"; fi
}

recon_leads_count() {
  local n=0 f
  for f in api_json quickhits_auth quickhits_interesting rescued browser_todo robots_targets; do
    n=$((n + $(count_lines "recon/$f.txt")))
  done
  printf '%s' "$n"
}

recon_leads_line() {
  local n; n="$(recon_leads_count)"
  if [ "$n" -gt 0 ]; then ui_ok leads "$n to look at (kestrel status for the list)"
  else ui_info leads "no automatic leads"; fi
}

# notify <text> — optional end-of-run notification, only if configured in the global config
notify() {
  [ -n "${NOTIFY_NTFY:-}${NOTIFY_DISCORD:-}${NOTIFY_TELEGRAM_TOKEN:-}" ] || return 0
  local msg="$1"
  [ -n "${NOTIFY_NTFY:-}" ] && curl -s -m 10 -d "$msg" "$NOTIFY_NTFY" >/dev/null
  [ -n "${NOTIFY_DISCORD:-}" ] && curl -s -m 10 -H 'Content-Type: application/json' \
      -d "$(jq -n --arg c "$msg" '{content:$c}')" "$NOTIFY_DISCORD" >/dev/null
  [ -n "${NOTIFY_TELEGRAM_TOKEN:-}" ] && [ -n "${NOTIFY_TELEGRAM_CHAT:-}" ] && curl -s -m 10 \
      "https://api.telegram.org/bot${NOTIFY_TELEGRAM_TOKEN}/sendMessage" \
      --data-urlencode "chat_id=${NOTIFY_TELEGRAM_CHAT}" --data-urlencode "text=$msg" >/dev/null
  return 0
}
