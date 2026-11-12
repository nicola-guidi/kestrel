# shellcheck shell=bash
# kestrel db <sub> — a per-program SQLite index for recalling everything kestrel collected.
#
#   The flat files in each program folder stay the source of truth; the db is a DERIVED,
#   additive store, rebuilt any time from those files. Each program has its OWN db file:
#   <program_dir>/kestrel.db (inspectable with the `sqlite3` CLI or any viewer — nothing hidden).
#
#   kestrel db sync [program]   read the program's files on disk into its db (idempotent)
#   kestrel db stats [program]  row counts per table
#   kestrel db host <name> [program]   dossier for one host: IPs, services, Shodan+CVE, endpoints, leads
#   kestrel db ip <addr> [program]     dossier for one IP: owning host(s), services, Shodan+CVE
#   kestrel db path <substr> [program] every host exposing a URL whose path matches <substr>
#   kestrel db view <kind> [program]   table view: hosts|services|ports|endpoints|vulns|leads
#   kestrel db query "<sql>" [program] run raw SQL on the program's db, tab-separated output
#
#   The program defaults to the last one you worked on. Each db holds only its own program — nothing
#   crosses between programs.

cmd_db() {
  local sub="${1:-}"; shift 2>/dev/null || true
  have python3 || ui_die "python3 is required" "kestrel doctor --install"

  case "$sub" in
    ""|-h|--help)
      sed -n '2,17p' "$KESTREL_ROOT/cmd/db.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;

    sync)
      local prog; prog="$(resolve_program "${1:-}")"; load_program "$prog"
      local db="$WORK/kestrel.db"
      ui_header db "$prog"
      local t0; t0=$(date +%s)
      ui_running db "ingesting $prog into its db (offline, reads files on disk)…"
      local out; out="$(python3 "$KESTREL_ROOT/lib/db.py" "$db" sync "$WORK" "$prog")" || ui_die "db sync failed"
      local D_HOSTS D_IPS D_HOST_IPS D_PORTS D_ENDPOINTS D_LEADS
      eval "$(printf '%s\n' "$out" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/D_\1=\x27\2\x27/')"
      ui_ok synced "${D_HOSTS:-0} hosts · ${D_IPS:-0} IPs · ${D_HOST_IPS:-0} host↔IP · ${D_PORTS:-0} ports · ${D_ENDPOINTS:-0} endpoints · ${D_LEADS:-0} leads"
      ui_blank
      ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · $db"
      ui_next "kestrel db host <name>   ·   kestrel db ip <addr>   ·   kestrel db stats"
      ui_blank ;;

    stats)
      local prog; prog="$(resolve_program "${1:-}")"; load_program "$prog"
      local db="$WORK/kestrel.db"
      ui_header db "$prog"
      [ -f "$db" ] || ui_die "no db yet for $prog" "kestrel db sync $prog"
      python3 "$KESTREL_ROOT/lib/db.py" "$db" stats | while IFS='=' read -r k v; do
        ui_info "$(printf '%s' "$k" | tr '[:upper:]' '[:lower:]')" "$v"
      done
      ui_blank ;;

    host|ip|path)
      [ -n "${1:-}" ] || ui_die "give a value" "kestrel db $sub <value> [program]"
      local val="$1"; shift 2>/dev/null || true
      local prog; prog="$(resolve_program "${1:-}")"; load_program "$prog"
      local db="$WORK/kestrel.db"
      [ -f "$db" ] || ui_die "no db yet for $prog" "kestrel db sync $prog"
      python3 "$KESTREL_ROOT/lib/db.py" "$db" "$sub" "$val" "$prog" ;;

    view)
      [ -n "${1:-}" ] || ui_die "give a kind" "kestrel db view hosts [program]"
      local kind="$1"; shift
      local prog; prog="$(resolve_program "${1:-}")"
      if [ -n "${1:-}" ] && [[ "$1" != -* ]]; then shift; fi
      load_program "$prog"
      local db="$WORK/kestrel.db"
      [ -f "$db" ] || ui_die "no db yet for $prog" "kestrel db sync $prog"
      python3 "$KESTREL_ROOT/lib/db.py" "$db" view "$kind" "$prog" "$@" ;;

    query)
      [ -n "${1:-}" ] || ui_die "give a SQL statement" 'kestrel db query "SELECT * FROM hosts" [program]'
      local sql="$1"; shift 2>/dev/null || true
      local prog; prog="$(resolve_program "${1:-}")"; load_program "$prog"
      local db="$WORK/kestrel.db"
      [ -f "$db" ] || ui_die "no db yet for $prog" "kestrel db sync $prog"
      python3 "$KESTREL_ROOT/lib/db.py" "$db" query "$sql" ;;

    *) ui_die "unknown 'db $sub'" "kestrel db --help" ;;
  esac
}
