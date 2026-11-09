# shellcheck shell=bash
# kestrel ports [program] — port & service intel.
#
#   1. passive: Shodan InternetDB on in-scope IPs + IPs of resolving in-scope hosts.
#      Free, no key, ZERO packets to the target. Always runs.
#   2. active: naabu + nmap -sV (engine bb-ports), ONLY if the program allows port scanning
#      (answered at onboarding). Host mode on resolved hosts, then range mode on the
#      in-scope IP ranges if the scope has any.
#
#   Ownership gate: the active scan only touches IPs inside an in-scope range or whose PTR is a
#   scope domain; IPs that in-scope hosts resolve to but that belong to third parties (SaaS/CDN)
#   are listed and skipped. Before scanning, the approved targets are previewed and confirmed.
#
#   --passive               only step 1 (Shodan), even if active scanning is allowed
#   -n, --dry-run           preview the approved targets only, never scan
#   -y, --yes               skip the confirmation prompt and scan the approved targets
#   --include-third-party   scan third-party IPs too (only if you are authorised to)

cmd_ports() {
  local prog="" passive_only=0 include_third=0 assume_yes=0 dry_run=0 a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,17p' "$KESTREL_ROOT/cmd/ports.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      --passive) passive_only=1 ;;
      --include-third-party) include_third=1 ;;
      -y|--yes) assume_yes=1 ;;
      -n|--dry-run) dry_run=1 ;;
      -*) ui_die "unknown option '$a'" "kestrel ports --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header ports "$prog"
  have python3 || ui_die "python3 is required" "kestrel doctor --install"

  local t0; t0=$(date +%s)
  local has_hosts=0 has_ranges=0
  [ -s recon/resolved.txt ] || [ -s recon/hosts.txt ] && has_hosts=1
  [ -s recon/ip_targets.txt ] && has_ranges=1
  if [ "$has_hosts" -eq 0 ] && [ "$has_ranges" -eq 0 ]; then
    ui_die "nothing to look at yet: no resolved hosts and no IP ranges" "kestrel recon $prog"
  fi
  [ "$has_hosts" -eq 0 ] && [ -n "$(cat recon/apex.txt 2>/dev/null)" ] && \
    ui_warn hosts "recon not run yet: only IP ranges will be checked"

  # ---------------------------------------------------------------- 1 · passive
  ui_section "passive · Shodan InternetDB (no traffic to the target)"
  local out="" idb_code
  idb_code="$(shodan_probe)"
  case "$idb_code" in
    200|404) out="$(python3 "$KESTREL_ROOT/lib/shodan_idb.py" "$WORK")" || ui_warn shodan "lookup failed" ;;
    *)       ui_warn shodan "InternetDB unreachable (${idb_code:-no answer}) — passive layer skipped" ;;
  esac
  local SH_IPS SH_QUERIED SH_KNOWN SH_PORTS SH_VULNS SH_SKIPPED_OOS SH_CAPPED SH_ERRORS
  eval "$(printf '%s\n' "$out" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/SH_\1=\x27\2\x27/')"
  if [ -z "$out" ]; then :
  elif [ "${SH_KNOWN:-0}" -gt 0 ]; then
    ui_ok shodan "${SH_KNOWN} of ${SH_QUERIED} IPs known · ${SH_PORTS} open ports · ${SH_VULNS} CVEs"
    sed 's/^/                 /' recon/ports/shodan.txt | head -n 10 >&2
    [ "$(count_lines recon/ports/shodan.txt)" -gt 10 ] && ui_dim "               … $(( $(count_lines recon/ports/shodan.txt) - 10 )) more in recon/ports/shodan.txt"
  else
    ui_info shodan "nothing known for ${SH_QUERIED:-0} IPs"
  fi
  [ "${SH_SKIPPED_OOS:-0}" -gt 0 ] && ui_ok scope "${SH_SKIPPED_OOS} out-of-scope IPs skipped"
  [ "${SH_CAPPED:-0}" -gt 0 ]      && ui_warn capped "${SH_CAPPED} IPs over the 4096 cap not checked"
  [ "${SH_ERRORS:-0}" -gt 0 ]      && ui_warn errors "${SH_ERRORS} lookups failed (network / rate limit)"

  # ---------------------------------------------------------------- 2 · active
  ui_section "active · naabu + nmap"
  if [ "$passive_only" -eq 1 ]; then
    ui_info active "skipped (--passive)"
  elif [ "${PORTSCAN_ALLOWED:-n}" != y ]; then
    ui_warn active "not allowed by the program: passive only"
  else
    local rc=0
    : > notes/ports.log

    # OWNERSHIP GATE: an in-scope host can resolve to a THIRD-PARTY IP (SaaS/CDN). Port-scanning
    # that IP hits someone else's infra. Scan ONLY IPs that are inside an in-scope range or whose
    # PTR is a scope domain. The rest are listed and skipped (unless --include-third-party).
    ui_running ownership "resolving in-scope hosts, checking IP ownership…"
    local ores; ores="$(python3 "$KESTREL_ROOT/lib/ownership.py" "$WORK" 2>/dev/null)" || true
    local OWNED THIRDPARTY
    eval "$(printf '%s\n' "$ores" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/\1=\x27\2\x27/')"
    if [ "${THIRDPARTY:-0}" -gt 0 ] && [ "$include_third" -eq 0 ]; then
      ui_warn third-party "${THIRDPARTY} IP(s) belong to third parties (SaaS/CDN) — NOT scanned · recon/ports/thirdparty.txt"
      sed 's/^/                 /' recon/ports/thirdparty.txt | head -n 6 >&2
    elif [ "${THIRDPARTY:-0}" -gt 0 ]; then
      ui_warn third-party "${THIRDPARTY} third-party IP(s) scanned anyway (--include-third-party) — make sure you are authorised"
      cut -f1 recon/ports/thirdparty.txt >> recon/ports/owned_ips.txt
    fi

    # build the approved IP list: owned resolved IPs + declared in-scope ranges
    local scanfile=recon/ports/scan_targets.txt
    { cat recon/ports/owned_ips.txt 2>/dev/null; [ -s recon/ip_targets.txt ] && cat recon/ip_targets.txt; } | sort -u > "$scanfile"
    local ntargets; ntargets="$(count_lines "$scanfile")"
    if [ ! -s "$scanfile" ]; then
      ui_warn active "no in-scope-owned IP to scan (all resolved IPs are third-party)"
    else
      # PREVIEW: show exactly what will be scanned, then require confirmation (-y skips it).
      ui_ok preview "${ntargets} approved target(s) that WILL be scanned · recon/ports/scan_targets.txt"
      sed 's/^/                 /' "$scanfile" | head -n 20 >&2
      [ "$ntargets" -gt 20 ] && ui_dim "               … $(( ntargets - 20 )) more in recon/ports/scan_targets.txt"
      if [ "$dry_run" -eq 1 ]; then
        ui_info active "dry run: nothing scanned (re-run with -y to launch)"
      elif [ "$assume_yes" -eq 0 ] && ! ui_yesno "Launch the active scan on ${ntargets} target(s)?" n; then
        ui_info active "skipped: not confirmed (re-run with -y to launch, or --dry-run to only preview)"
      else
        ui_running active "naabu + nmap on ${ntargets} approved target(s)…"
        CIDR_FILE="$WORK/$scanfile" PORTS="${PORTS:--top-ports 100}" \
          TOOLLOG="$WORK/notes/tools.log" bash "$KESTREL_ROOT/libexec/bb-ports.sh" --ranges -y >> notes/ports.log 2>&1 || rc=1
        ui_ok active "$(count_lines recon/ports/naabu.txt) open ports · $(count_lines recon/ports/services.txt) services on ${ntargets} owned target(s)"
        # FIREWALL GUARD: a host that answers on an improbable number of ports is a filtering
        # device (SYN-ACK / tcpwrapped on everything), not real services. Flag it so the count
        # above isn't mistaken for genuine open ports.
        awk -F: 'NF==2{c[$1]++} END{for(i in c) if(c[i]>=FW) print i"\t"c[i]}' FW="${FW_PORT_THRESHOLD:-30}" \
          recon/ports/naabu.txt 2>/dev/null | sort -V > recon/ports/firewalled.txt
        local nfw; nfw="$(count_lines recon/ports/firewalled.txt)"
        [ "$nfw" -gt 0 ] && ui_warn firewalled "${nfw} IP(s) answer on ≥${FW_PORT_THRESHOLD:-30} ports — likely a firewall, not real services · recon/ports/firewalled.txt"
      fi
    fi
    [ "${OWNED:-0}" -gt 0 ] && ui_info owned "${OWNED} IP(s) resolved from in-scope hosts, inside scope"
    if [ "$rc" -ne 0 ]; then ui_warn active "finished with issues · notes/ports.log"; fi
    [ -s recon/ports/services.txt ] && ui_info services "recon/ports/services.txt"
  fi

  ui_blank
  ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · results in recon/ports/"
  ui_next "kestrel status $prog"
  ui_blank
}

# ports_stash <mode> — move one engine run's files into recon/ports/<mode>/ (the engine reuses names)
ports_stash() {
  local d="recon/ports/$1" f
  rm -rf "$d"; mkdir -p "$d"
  for f in ips.txt naabu.txt services.txt ip_ports.txt _hosts.txt _httpx_ip.txt report.html nmap; do
    [ -e "recon/ports/$f" ] && mv "recon/ports/$f" "$d/"
  done
  return 0
}
