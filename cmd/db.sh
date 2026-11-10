# shellcheck shell=bash
# kestrel db <sub> — optional SQLite index for cross-referencing data across programs.
#
#   The flat files in each program folder stay the source of truth; the db is a DERIVED,
#   additive store, rebuilt any time from those files. One shared file: <workspace>/kestrel.db
#   (inspectable with the `sqlite3` CLI or any viewer — nothing hidden).
#
#   kestrel db sync [program]   read the program's files on disk into the db (idempotent)
#   kestrel db stats            row counts per table
#   kestrel db host <name>      full dossier for one host: IPs, services, Shodan+CVE, endpoints, leads
#   kestrel db ip <addr>        full dossier for one IP: owning host(s), services, Shodan+CVE
#   kestrel db path <substr>    every host exposing a URL whose path matches <substr>
#   kestrel db view <kind> ...  table view: hosts|services|ports|endpoints|vulns|leads
#   kestrel db query "<sql>"    run raw SQL, tab-separated output
#   kestrel db shared-ips       IPs that appear in more than one program
#   kestrel db shared-hosts     registrable domains seen in more than one program

cmd_db() {
  local sub="${1:-}"; shift 2>/dev/null || true
  local db="$KESTREL_BASE/kestrel.db"
  have python3 || ui_die "python3 is required" "kestrel doctor --install"

  case "$sub" in
    ""|-h|--help)
      sed -n '2,16p' "$KESTREL_ROOT/cmd/db.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;

    sync)
      local prog; prog="$(resolve_program "${1:-}")"; load_program "$prog"
      ui_header db "$prog"
      local t0; t0=$(date +%s)
      ui_running db "ingesting $prog into the shared db (offline, reads files on disk)…"
      local out; out="$(python3 "$KESTREL_ROOT/lib/db.py" "$db" sync "$WORK" "$prog")" || ui_die "db sync failed"
      local D_HOSTS D_IPS D_HOST_IPS D_PORTS D_ENDPOINTS D_LEADS
      eval "$(printf '%s\n' "$out" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/D_\1=\x27\2\x27/')"
      ui_ok synced "${D_HOSTS:-0} hosts · ${D_IPS:-0} IPs · ${D_HOST_IPS:-0} host↔IP · ${D_PORTS:-0} ports · ${D_ENDPOINTS:-0} endpoints · ${D_LEADS:-0} leads"
      ui_blank
      ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · $db"
      ui_next "kestrel db host <name>   ·   kestrel db ip <addr>   ·   kestrel db stats"
      ui_blank ;;

    stats)
      ui_header db "$(basename "$db")"
      [ -f "$db" ] || ui_die "no db yet" "kestrel db sync"
      python3 "$KESTREL_ROOT/lib/db.py" "$db" stats | while IFS='=' read -r k v; do
        ui_info "$(printf '%s' "$k" | tr '[:upper:]' '[:lower:]')" "$v"
      done
      ui_blank ;;

    host|ip|path)
      [ -f "$db" ] || ui_die "no db yet" "kestrel db sync"
      [ -n "${1:-}" ] || ui_die "give a value" "kestrel db $sub <value> [program|--all]"
      local val="$1"; shift 2>/dev/null || true
      python3 "$KESTREL_ROOT/lib/db.py" "$db" "$sub" "$val" "${1:---all}" ;;

    view)
      [ -f "$db" ] || ui_die "no db yet" "kestrel db sync"
      [ -n "${1:-}" ] || ui_die "give a kind" "kestrel db view hosts <program|--all>"
      local kind="$1"; shift
      local prog="--all"
      if [ -n "${1:-}" ] && [[ "$1" != -* ]]; then prog="$(resolve_program "$1")"; shift; fi
      python3 "$KESTREL_ROOT/lib/db.py" "$db" view "$kind" "$prog" "$@" ;;

    query)
      [ -f "$db" ] || ui_die "no db yet" "kestrel db sync"
      [ -n "${1:-}" ] || ui_die "give a SQL statement" 'kestrel db query "SELECT * FROM programs"'
      python3 "$KESTREL_ROOT/lib/db.py" "$db" query "$*" ;;

    shared-ips|shared-hosts)
      [ -f "$db" ] || ui_die "no db yet" "kestrel db sync"
      python3 "$KESTREL_ROOT/lib/db.py" "$db" "$sub" ;;

    *) ui_die "unknown 'db $sub'" "kestrel db --help" ;;
  esac
}
