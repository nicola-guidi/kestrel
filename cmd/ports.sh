# shellcheck shell=bash
# kestrel ports [program] — active port & service scan.
#
#   ACTIVE scan (naabu + nmap -sV, real packets), ONLY if the program allows port scanning
#   (answered at onboarding). Targets are EXACTLY the in-scope IP ranges/IPs you declared at
#   onboarding, minus the out-of-scope ones (recon/ip_targets.txt). It does NOT resolve in-scope
#   hostnames to IPs and scan those — a host resolving to some IP does not authorise scanning
#   that IP. If the program declares no IP ranges, there is nothing to scan here.
#
#   Passive intel (Shodan InternetDB, zero packets) is a separate step:  kestrel shodan
#
#   -n, --dry-run   preview the approved targets only, never scan
#   -y, --yes       skip the confirmation prompt and scan
#   --fresh         ignore a previous run's progress and rescan everything from scratch
#
#   An interrupted scan resumes automatically on the next run: the finished naabu phase is
#   reused and per-IP nmap results already collected are skipped. Use --fresh to start over.

cmd_ports() {
  local prog="" assume_yes=0 dry_run=0 fresh=0 a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,17p' "$KESTREL_ROOT/cmd/ports.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      -y|--yes) assume_yes=1 ;;
      -n|--dry-run) dry_run=1 ;;
      --fresh) fresh=1 ;;
      -*) ui_die "unknown option '$a'" "kestrel ports --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header ports "$prog"

  local t0; t0=$(date +%s)
  ui_section "active · naabu + nmap"
  if [ "${PORTSCAN_ALLOWED:-n}" != y ]; then
    ui_warn active "not allowed by the program — skipped"
    ui_info passive "for passive port intel without traffic:  kestrel shodan $prog"
    ui_blank; return 0
  fi
  if [ ! -s recon/ip_targets.txt ]; then
    ui_warn active "the program declares no in-scope IP ranges — nothing to port-scan"
    ui_info passive "for passive port intel without traffic:  kestrel shodan $prog"
    ui_blank; return 0
  fi

  local rc=0
  : > notes/ports.log

  # Targets = EXACTLY the declared in-scope ranges/IPs (already net of out-of-scope). No host
  # resolution, no ownership guessing: only what the program authorises for Network testing.
  local scanfile=recon/ports/scan_targets.txt
  mkdir -p recon/ports
  sort -u recon/ip_targets.txt > "$scanfile"
  local ntargets; ntargets="$(count_lines "$scanfile")"

  # PREVIEW: show exactly what will be scanned, then require confirmation (-y skips it).
  ui_ok preview "${ntargets} declared in-scope range(s)/IP(s) that WILL be scanned · recon/ports/scan_targets.txt"
  sed 's/^/                 /' "$scanfile" | head -n 20 >&2
  [ "$ntargets" -gt 20 ] && ui_dim "               … $(( ntargets - 20 )) more in recon/ports/scan_targets.txt"

  if [ "$dry_run" -eq 1 ]; then
    ui_info active "dry run: nothing scanned (re-run with -y to launch)"
  elif [ "$assume_yes" -eq 0 ] && ! ui_yesno "Launch the active scan on ${ntargets} declared target(s)?" n; then
    ui_info active "skipped: not confirmed (re-run with -y to launch, or --dry-run to only preview)"
  else
    ui_running active "naabu + nmap on ${ntargets} declared target(s)…"
    local _fresh=(); [ "$fresh" -eq 1 ] && _fresh=(--fresh)
    # PORTS left to bb-ports' RANGE_PORTS_DEFAULT (curated range ports) unless the user exported one.
    CIDR_FILE="$WORK/$scanfile" PORTS="${PORTS:-}" \
      TOOLLOG="$WORK/notes/tools.log" bash "$KESTREL_ROOT/libexec/bb-ports.sh" --ranges "${_fresh[@]}" -y >> notes/ports.log 2>&1 || rc=1
    ui_ok active "$(count_lines recon/ports/naabu.txt) open ports · $(count_lines recon/ports/services.txt) services on ${ntargets} declared target(s)"
    # FIREWALL GUARD: a host that answers on an improbable number of ports is a filtering
    # device (SYN-ACK / tcpwrapped on everything), not real services. Flag it so the count
    # above isn't mistaken for genuine open ports.
    awk -F: 'NF==2{c[$1]++} END{for(i in c) if(c[i]>=FW) print i"\t"c[i]}' FW="${FW_PORT_THRESHOLD:-30}" \
      recon/ports/naabu.txt 2>/dev/null | sort -V > recon/ports/firewalled.txt
    local nfw; nfw="$(count_lines recon/ports/firewalled.txt)"
    [ "$nfw" -gt 0 ] && ui_warn firewalled "${nfw} IP(s) answer on ≥${FW_PORT_THRESHOLD:-30} ports — likely a firewall, not real services · recon/ports/firewalled.txt"
  fi
  if [ "$rc" -ne 0 ]; then ui_warn active "finished with issues · notes/ports.log"; fi
  [ -s recon/ports/services.txt ] && ui_info services "recon/ports/services.txt"

  ui_blank
  ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · results in recon/ports/"
  ui_next "kestrel shodan $prog   ·   kestrel triage $prog"
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
