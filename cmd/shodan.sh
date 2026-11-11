# shellcheck shell=bash
# kestrel shodan [program] — passive port intel via Shodan InternetDB.
#
#   A separate, PASSIVE step (zero packets to the target). It queries Shodan's free InternetDB
#   over everything recon collected, in priority order so the budget hits live assets first:
#     1. IPs the in-scope hostnames resolve to
#     2. live IPs with open ports from 'kestrel ports'
#     3. a distributed sample across the declared in-scope ranges
#
#   Third-party IPs (a host resolving to SaaS/CDN infra the target does not own) are excluded
#   entirely — never queried, never written — only counted. Out-of-scope IPs are never touched.
#
#   --max <n>   cap the number of IPs queried (default 4096, the free-API budget)

cmd_shodan() {
  local prog="" max=4096 a
  while [ $# -gt 0 ]; do
    a="$1"
    case "$a" in
      -h|--help) sed -n '2,13p' "$KESTREL_ROOT/cmd/shodan.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      --max) shift; max="${1:-4096}" ;;
      --max=*) max="${a#*=}" ;;
      -*) ui_die "unknown option '$a'" "kestrel shodan --help" ;;
      *) prog="$a" ;;
    esac
    shift
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header shodan "$prog"
  have python3 || ui_die "python3 is required" "kestrel doctor --install"
  [ -s recon/ip_targets.txt ] || [ -s recon/resolved.txt ] || [ -s recon/hosts.txt ] || [ -s recon/ports/naabu.txt ] \
    || ui_die "no IPs to look up yet (no ranges, resolved hosts, or port-scan results)" "kestrel recon $prog"

  local t0; t0=$(date +%s)
  ui_section "passive · Shodan InternetDB (no traffic to the target)"
  local idb_code; idb_code="$(shodan_probe)"
  case "$idb_code" in
    200|404) : ;;
    *) ui_die "InternetDB unreachable (${idb_code:-no answer}) — check your connection" "kestrel doctor" ;;
  esac

  ui_running shodan "querying InternetDB over the collected IPs (live assets first)…"
  local out; out="$(python3 "$KESTREL_ROOT/lib/shodan_idb.py" "$WORK" "$max")" || ui_die "shodan lookup failed"
  local SH_IPS SH_QUERIED SH_KNOWN SH_PORTS SH_VULNS SH_SKIPPED_OOS SH_THIRDPARTY_EXCLUDED SH_CAPPED SH_ERRORS SH_INTERRUPTED
  eval "$(printf '%s\n' "$out" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/SH_\1=\x27\2\x27/')"

  if [ "${SH_KNOWN:-0}" -gt 0 ]; then
    ui_ok shodan "${SH_KNOWN} of ${SH_QUERIED:-0} queried IPs known · ${SH_PORTS:-0} open ports · ${SH_VULNS:-0} CVEs · recon/ports/shodan.txt"
    sed 's/^/                 /' recon/ports/shodan.txt | head -n 10 >&2
    [ "$(count_lines recon/ports/shodan.txt)" -gt 10 ] && ui_dim "               … $(( $(count_lines recon/ports/shodan.txt) - 10 )) more in recon/ports/shodan.txt"
  else
    ui_info shodan "nothing known for the ${SH_QUERIED:-0} IPs queried"
  fi
  [ "${SH_THIRDPARTY_EXCLUDED:-0}" -gt 0 ] && ui_ok scope "${SH_THIRDPARTY_EXCLUDED} third-party IP(s) excluded (not the target's)"
  [ "${SH_SKIPPED_OOS:-0}" -gt 0 ]        && ui_ok scope "${SH_SKIPPED_OOS} out-of-scope IP(s) skipped"
  [ "${SH_CAPPED:-0}" -gt 0 ]             && ui_info capped "${SH_CAPPED} IP(s) over the ${max} cap not checked (raise with --max)"
  [ "${SH_ERRORS:-0}" -gt 0 ]             && ui_warn errors "${SH_ERRORS} lookup(s) failed (network / rate limit)"
  [ "${SH_INTERRUPTED:-0}" = 1 ]          && ui_warn interrupted "stopped early (Ctrl-C) — the ${SH_KNOWN:-0} known IP(s) so far are saved · re-run for a full pass"

  ui_blank
  ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · recon/ports/shodan.*"
  ui_next "kestrel triage $prog"
  ui_blank
}
