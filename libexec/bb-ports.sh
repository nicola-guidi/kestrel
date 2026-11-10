#!/usr/bin/env bash
# bb-ports.sh — port scan + service detection, for scopes that EXPLICITLY allow it.
#
# Chain (all against the TARGET, real packets):
#   1. input  : resolving hosts from a bb-recon run (default recon/resolved.txt)
#   2. httpx  : resolve each host to its IP(s) → unique target IP list
#   3. naabu  : port scan those IPs (CDN IPs are NOT full-scanned — only 80/443)
#   4. nmap   : -sV service/version detection on the ports naabu found
#
# This sends ACTIVE, noisy traffic. Run it ONLY on hosts whose program permits port
# scanning, and whose IPs the target actually OWNS (not shared CDN/cloud infra). It will
# NOT run until you confirm authorization with -y (or PORTSCAN_OK=1).
#
# Output lands under recon/ports/ — the main recon files are never touched.
# Reuses the program env:  source env.sh first.
#
# Usage:
#   source ~/hunts/<prog>/env.sh && ~/hunts/bb-ports.sh -y
#   ~/hunts/bb-ports.sh -y ~/hunts/<prog>              # or pass the folder
#   ~/hunts/bb-ports.sh -y recon/surface_ok.txt            # or a custom host list
#   PORT_RATE=150 ~/hunts/bb-ports.sh -y                   # gentler on a home line/IDS
#   PORTS='-p -' ~/hunts/bb-ports.sh -y                    # full 65535 (very noisy)
#   ~/hunts/bb-ports.sh --ranges -y                        # RANGE mode: scan the program's IP ranges
#                                       # (recon/ip_targets.txt, written by bb-init) directly, no resolve;
#                                       # recon/cidr_oos.txt is never touched (naabu -exclude-hosts)
#   CIDR_FILE=my_ranges.txt ~/hunts/bb-ports.sh -y         # RANGE mode on a custom IP/CIDR list
#   ~/hunts/bb-ports.sh --ranges -y          # auto-resumes an interrupted scan; --fresh = full rescan
#
# RESUME: a long scan can be interrupted (Ctrl-C) and re-run — it reuses the finished naabu
# phase (checkpoint recon/ports/.naabu.done) and skips per-IP nmap files already completed.
# Pass --fresh to wipe that state and rescan everything from scratch.
#
# Exit 0 = ran (or dry preview without -y). Exit >0 = a real problem.
set -euo pipefail
export LC_ALL=C

# ---------------------------------------------------------------- output helpers
log()  { printf '\033[1;36m[bb-ports %s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()   { printf '   \033[1;32m✓\033[0m %s\n' "$*" >&2; }
warn() { printf '   \033[1;33m⚠\033[0m  %s\n' "$*" >&2; }
sub()  { printf '     \033[2m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[bb-ports] ✗ %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" || die "missing '$1' in PATH. Install it first (naabu/nmap/httpx)."; }
esc()  { printf '%s' "$1" | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

# ---------------------------------------------------------------- HTML report (no traffic)
# Self-contained report.html from the files already in recon/ports/. Safe to call anytime.
emit_report() {
  local R="recon/ports/report.html" nip nopen nhost when prog cdntag=""
  nip=$(   [ -f recon/ports/ips.txt ]    && wc -l < recon/ports/ips.txt    || echo 0 )
  nopen=$( [ -f recon/ports/naabu.txt ]  && wc -l < recon/ports/naabu.txt  || echo 0 )
  nhost=$( [ -f recon/ports/_hosts.txt ] && wc -l < recon/ports/_hosts.txt || echo 0 )
  when=$(date '+%Y-%m-%d %H:%M'); prog=$(esc "${PROGRAM:-$(basename "$WORK")}")
  [ "$EXCLUDE_CDN" = 1 ] && cdntag=" · exclude-cdn"
  {
    cat <<HEAD
<!doctype html><html lang=en><head><meta charset=utf-8>
<title>bb-ports — $prog</title><meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--bg:#0e1116;--card:#161b22;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--accent:#58a6ff;--bad:#f85149}
*{box-sizing:border-box}body{margin:0 auto;max-width:1000px;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,Segoe UI,Roboto,sans-serif;padding:24px}
h1{font-size:20px;margin:0 0 2px}h2{font-size:15px;margin:26px 0 8px;color:var(--accent)}
.mut{color:var(--mut);font-size:12px}
.stats{display:flex;gap:26px;flex-wrap:wrap;margin:16px 0}
.stat{font-size:26px;font-weight:700}.stat small{display:block;font-size:11px;font-weight:400;color:var(--mut)}
table{border-collapse:collapse;width:100%;font-size:13px;margin-top:4px}
th,td{text-align:left;padding:6px 9px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut);font-weight:600}code{font-family:ui-monospace,Menlo,Consolas,monospace}
tr.hot td{background:rgba(248,81,73,.09)}tr.hot td:first-child{border-left:3px solid var(--bad)}
.note{color:var(--mut);font-size:12px;margin-top:20px;border-top:1px solid var(--line);padding-top:10px}
.empty{color:var(--mut);font-style:italic}
</style></head><body>
<h1>bb-ports · $prog</h1>
<div class=mut>$when · rate $PORT_RATE pps · porte $(esc "$PORTS")$cdntag</div>
<div class=stats>
  <div class=stat>$nhost<small>host in scope</small></div>
  <div class=stat>$nip<small>IP unici</small></div>
  <div class=stat>$nopen<small>porte aperte</small></div>
</div>
<h2>Servizi rilevati</h2>
HEAD
    if [ -s recon/ports/services.txt ]; then
      echo '<table><tr><th>IP</th><th>porta</th><th>stato</th><th>servizio</th><th>versione</th></tr>'
      awk 'function esc(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}
           BEGIN{split("21 22 23 25 111 135 139 389 445 873 1433 1521 2049 2375 2379 3000 3306 3389 5432 5601 5900 5984 5985 6379 6443 7001 8500 9000 9090 9200 10250 11211 15672 27017",A," ");for(i in A)hot[A[i]]=1}
           {ip=$1;pp=$2;st=$3;svc=$4;ver="";for(i=5;i<=NF;i++)ver=ver (i>5?" ":"") $i;
            split(pp,p,"/");cls=(p[1] in hot)?" class=hot":"";
            printf "<tr%s><td><code>%s</code></td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>\n",cls,esc(ip),esc(pp),esc(st),esc(svc),esc(ver)}' recon/ports/services.txt
      echo '</table>'
    elif [ -s recon/ports/naabu.txt ]; then
      echo '<p class=mut>nmap senza dettagli; porte aperte grezze:</p><table><tr><th>IP:porta</th></tr>'
      awk 'function esc(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}{printf "<tr><td><code>%s</code></td></tr>\n",esc($0)}' recon/ports/naabu.txt
      echo '</table>'
    else
      echo '<p class=empty>Nessuna porta aperta trovata.</p>'
    fi
    echo '<h2>Mappa host → IP (httpx)</h2>'
    if [ -s recon/ports/_httpx_ip.txt ]; then
      echo '<table><tr><th>host [IP]</th></tr>'
      awk 'function esc(s){gsub(/&/,"\\&amp;",s);gsub(/</,"\\&lt;",s);gsub(/>/,"\\&gt;",s);return s}{printf "<tr><td><code>%s</code></td></tr>\n",esc($0)}' recon/ports/_httpx_ip.txt
      echo '</table>'
    else
      echo '<p class=empty>—</p>'
    fi
    cat <<'FOOT'
<div class=note>Conferma che ogni servizio sia davvero esposto e <b>in scope</b> prima di segnalare. Niente brute-force: una prova, PoC minimo. Gli IP CDN/cloud condivisi non vanno scansionati a fondo.</div>
</body></html>
FOOT
  } > "$R"
}

# ---------------------------------------------------------------- flags
# -y / --yes : confirm you are authorized to port-scan these hosts (required to send packets).
YES=0
RANGES=0
FRESH=0
_args=()
for _a in "$@"; do
  case "$_a" in
    -y|--yes) YES=1 ;;
    --ranges) RANGES=1 ;;
    --fresh)  FRESH=1 ;;
    *)        _args+=("$_a") ;;
  esac
done
if [ "${#_args[@]}" -gt 0 ]; then set -- "${_args[@]}"; else set --; fi
[ "${PORTSCAN_OK:-0}" = 1 ] && YES=1

# ---------------------------------------------------------------- find the program folder
# First positional may be the program folder OR a host-list file. Decide by what it is.
HOSTS_ARG=""
WORK="${WORK:-}"
if [ -n "${1:-}" ]; then
  if [ -d "$1" ]; then WORK="$1"
  elif [ -f "$1" ]; then HOSTS_ARG="$1"
  else die "argument '$1' is neither a program folder nor a host-list file."; fi
fi
[ -z "$WORK" ] && [ -n "${PROGRAM:-}" ] && WORK="$HOME/hunts/$PROGRAM"
if [ -z "$WORK" ] || [ ! -d "$WORK" ]; then
  die "program folder not found. Run:  source ~/hunts/<prog>/env.sh && ~/hunts/bb-ports.sh -y"
fi
cd "$WORK"
mkdir -p recon recon/ports recon/ports/nmap notes

# RESUME: a long active scan can be interrupted and picked up later. The naabu phase writes a
# checkpoint (.naabu.done) only when it finishes; a completed per-IP nmap file (ends in "Nmap
# done") is reused instead of rescanned. --fresh wipes all of that and rescans from scratch.
if [ "${FRESH:-0}" = 1 ]; then
  rm -f recon/ports/.naabu.done recon/ports/naabu.txt recon/ports/ip_ports.txt recon/ports/services.txt
  rm -f recon/ports/nmap/*.txt 2>/dev/null || true
  log "fresh: cleared previous naabu/nmap results — full rescan"
fi

# ---------------------------------------------------------------- config
: "${UA:=Mozilla/5.0}"
: "${OOS_FILE:=$WORK/recon/oos.txt}"
: "${DNS_RESOLVERS:=1.1.1.1,8.8.8.8,9.9.9.9}"
: "${TOOLLOG:=$WORK/notes/tools.log}"
# ONE rate value, used for BOTH naabu (-rate, packets/sec) and nmap (--max-rate, packets/sec).
# Port scanning is inherently noisy: on a home line behind pfSense/Snort, keep this LOW
# (150–300). Default 150 = polite even if launched by mistake. Raise it (300/1000+) only on purpose.
: "${PORT_RATE:=150}"
# naabu port spec. Default = top 100 in host mode; in RANGE mode (thousands of IPs) a curated
# list of ports where an exposed service is itself a likely finding (unauth DB/cache, admin
# panels, remote access, container/k8s APIs, NFS/rsync, alt-HTTP). Override:
#   PORTS='-top-ports 1000'   ·   PORTS='-p 1-65535'   ·   PORTS='-p 22,80,443,3306,6379'
RANGE_PORTS_DEFAULT='-p 21,22,23,80,111,389,443,445,873,1433,1521,2049,2375,2379,3000,3306,3389,4443,5000,5432,5601,5900,5984,5985,6379,6443,7001,8000,8080,8443,8500,8888,9000,9090,9200,9443,10250,10443,11211,15672,27017'
: "${PORTS:=}"
# Skip full-scanning CDN IPs (only 80/443 there): protects shared cloud infra you don't own.
: "${EXCLUDE_CDN:=1}"
# RANGE mode: a file of IPs/CIDRs (one per line) scanned as-is, skipping host resolution.
: "${CIDR_FILE:=}"
# IPs/CIDRs to NEVER scan (file, or comma-separated list) → naabu -exclude-hosts. Any mode.
# Defaults to recon/cidr_oos.txt when the program has one (CIDR_EXCLUDE= to disable).
[ -z "${CIDR_EXCLUDE+x}" ] && [ -s "$WORK/recon/cidr_oos.txt" ] && CIDR_EXCLUDE="$WORK/recon/cidr_oos.txt"
: "${CIDR_EXCLUDE:=}"
[ "$RANGES" = 1 ] && [ -z "$CIDR_FILE" ] && CIDR_FILE="$WORK/recon/ip_targets.txt"
MODE=hosts; [ -n "$CIDR_FILE" ] && MODE=cidr
if [ -z "$PORTS" ]; then [ "$MODE" = cidr ] && PORTS="$RANGE_PORTS_DEFAULT" || PORTS='-top-ports 100'; fi
EXCL=""
if [ -n "$CIDR_EXCLUDE" ]; then
  if [ -f "$CIDR_EXCLUDE" ]; then EXCL=$(grep -vE '^[[:space:]]*(#|$)' "$CIDR_EXCLUDE" | paste -sd, -)
  else EXCL="$CIDR_EXCLUDE"; fi
fi
HDRS=(-H "User-Agent: $UA")

# ---------------------------------------------------------------- pick the input host list
H="recon/ports/_hosts.txt"
if [ "$MODE" = cidr ]; then
  [ -s "$CIDR_FILE" ] || die "CIDR_FILE '$CIDR_FILE' missing or empty (no IP ranges in scope? re-run bb-init with the IP/CIDR entries)."
  SRC="$CIDR_FILE"; : > "$H"
  NH=$(grep -cvE '^[[:space:]]*(#|$)' "$CIDR_FILE")
else
SRC="${HOSTS_ARG:-}"
if [ -z "$SRC" ]; then
  for c in recon/resolved.txt recon/live.txt recon/hosts.txt; do
    [ -s "$c" ] && { SRC="$c"; break; }
  done
fi
[ -n "$SRC" ] && [ -s "$SRC" ] || die "no input hosts. Run bb-recon 'live' first, or pass a host-list file."

# bare hostnames (strip scheme / httpx trailing fields / path / port), OOS-filtered
sed -E 's#^https?://##; s#[[:space:]].*$##; s#[/:].*$##' "$SRC" | sort -u > "$H"
if [ -s "$OOS_FILE" ]; then
  grep -ivFf "$OOS_FILE" "$H" > "$H.tmp" || true; mv "$H.tmp" "$H"
fi
NH=$(wc -l < "$H")
[ "$NH" -gt 0 ] || die "0 in-scope hosts after the OOS filter — nothing to scan."
fi

# ---------------------------------------------------------------- authorization gate
if [ "$YES" -ne 1 ]; then
  log "DRY PREVIEW (no packets sent). To actually scan, re-run with -y."
  printf '\n' >&2
  warn "Port scanning is ACTIVE and noisy. Before you add -y, confirm ALL of these:"
  sub "□ the program's policy EXPLICITLY allows active port scanning"
  sub "□ the IPs belong to the TARGET, not shared CDN/cloud (naabu -exclude-cdn helps, not a guarantee)"
  sub "□ the rate ($PORT_RATE pps) is acceptable for your line / won't trip your own IDS"
  printf '\n' >&2
  if [ "$MODE" = cidr ]; then
    log "RANGE mode: would scan $NH range(s)/IP(s) from $SRC directly (no httpx resolve)"
  else
    log "Would scan: $NH in-scope host(s) from $SRC"
  fi
  [ -n "$EXCL" ] && log "Never touched (naabu -exclude-hosts): $EXCL"
  [ "$MODE" = cidr ] && log "Chain: naabu ($PORTS, rate $PORT_RATE$([ "$EXCLUDE_CDN" = 1 ] && echo ', exclude-cdn')) → nmap -sV (--max-rate $PORT_RATE)" || log "Chain: httpx -ip → naabu ($PORTS, rate $PORT_RATE$([ "$EXCLUDE_CDN" = 1 ] && echo ', exclude-cdn')) → nmap -sV (--max-rate $PORT_RATE)"
  log "Re-run when ready:  ~/hunts/bb-ports.sh $([ "$RANGES" = 1 ] && echo "--ranges ")-y"
  exit 0
fi

# ================================================================ 1. resolve hosts → IPs (httpx)
IPS="recon/ports/ips.txt"
if [ "$MODE" = cidr ]; then
  grep -vE '^[[:space:]]*(#|$)' "$CIDR_FILE" | sed 's/[[:space:]]//g' | sort -u > "$IPS"
  NIP=$(wc -l < "$IPS")
  ok "RANGE mode: $NIP range(s)/IP(s) from $CIDR_FILE → $IPS (no resolve)"
else
need httpx
log "httpx: resolving $NH host(s) to IP addresses (rl $PORT_RATE)"
RAW="recon/ports/_httpx_ip.txt"
httpx -l "$H" "${HDRS[@]}" -ip -r "$DNS_RESOLVERS" \
  -t 50 -timeout 5 -rl "$PORT_RATE" -silent -o "$RAW" >>"$TOOLLOG" 2>&1 || true
touch "$RAW"
grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' "$RAW" | sort -u -V > "$IPS"
NIP=$(wc -l < "$IPS")
[ "$NIP" -gt 0 ] || die "httpx resolved 0 IPs (see $TOOLLOG). Hosts dead, or a tool/header problem."
ok "unique target IPs: $NIP → $IPS"
sub "host↔IP map kept in $RAW (verify these IPs are really the target's, not CDN)."
fi

# ================================================================ 2. port scan (naabu)
need naabu
CDNFLAG=(); [ "$EXCLUDE_CDN" = 1 ] && CDNFLAG=(-exclude-cdn)
[ -n "$EXCL" ] && CDNFLAG+=(-exclude-hosts "$EXCL")
NAABU="recon/ports/naabu.txt"
if [ -f recon/ports/.naabu.done ] && [ -s "$NAABU" ]; then
  ok "naabu: resuming — reusing $(wc -l < "$NAABU") open port(s) from a previous run (--fresh to rescan)"
else
  rm -f recon/ports/.naabu.done
  log "naabu: port scan over $NIP $([ "$MODE" = cidr ] && echo "range(s)/IP(s)" || echo "IP(s)") — $PORTS, rate $PORT_RATE pps${EXCLUDE_CDN:+ , exclude-cdn}"
  # shellcheck disable=SC2086  # $PORTS is an intentional multi-token flag spec
  naabu -list "$IPS" -rate "$PORT_RATE" $PORTS "${CDNFLAG[@]}" \
    -silent -o "$NAABU" >>"$TOOLLOG" 2>&1 || true
  touch "$NAABU"
  # Checkpoint the naabu phase ONLY now: a Ctrl-C mid-scan never reaches this line, so an
  # interrupted naabu re-runs in full next time. Once it is done, nmap resumes per-IP below.
  touch recon/ports/.naabu.done
fi
NOPEN=$(wc -l < "$NAABU")
if [ "$NOPEN" -eq 0 ]; then
  log "naabu found 0 open ports. Done (nothing for nmap)."
  emit_report
  ok "results in recon/ports/ (ips.txt; report.html)."
  exit 0
fi
ok "open ports found: $NOPEN (ip:port) → $NAABU"

# group ports per IP for nmap:  "<ip> <p1,p2,...>"
IPPORTS="recon/ports/ip_ports.txt"
awk -F: 'NF==2 { if ($1 in p) p[$1]=p[$1]","$2; else p[$1]=$2 } END{for(i in p) print i" "p[i]}' "$NAABU" \
  | sort -V > "$IPPORTS"

# ================================================================ 3. service detection (nmap -sV)
need nmap
log "nmap -sV on $(wc -l < "$IPPORTS") IP(s), only the open ports (--max-rate $PORT_RATE). -Pn (naabu already proved them up)."
# RESUME: a per-IP nmap file that ends in "Nmap done" is complete → reuse it, don't rescan.
# services.txt is rebuilt from scratch every run (from the CURRENT ip_ports.txt), so skipping
# finished IPs is idempotent and stale IPs from an old scope never linger.
: > recon/ports/services.txt
_ndone=0; _nskip=0
while read -r ip ports; do
  [ -z "$ip" ] && continue
  nf="recon/ports/nmap/${ip}.txt"
  if [ -f "$nf" ] && grep -q "Nmap done" "$nf" 2>/dev/null; then
    _nskip=$((_nskip+1)); sub "nmap → $ip (done earlier, skipping)"
  else
    sub "nmap → $ip ($ports)"
    nmap -sV -Pn -T3 --max-rate "$PORT_RATE" -p "$ports" "$ip" \
      -oN "$nf" -oG - >>"$TOOLLOG" 2>&1 || true
    _ndone=$((_ndone+1))
  fi
  # pull the readable "port  state  service  version" lines into one combined file
  if [ -f "$nf" ]; then
    awk -v ip="$ip" '/^[0-9]+\/(tcp|udp)/{printf "%-18s %s\n", ip, $0}' "$nf" \
      >> recon/ports/services.txt || true
  fi
done < "$IPPORTS"
[ "$_nskip" -gt 0 ] && ok "nmap resume: $_nskip IP(s) reused from a previous run, $_ndone newly scanned (--fresh to redo all)"
ok "service detection done → recon/ports/services.txt (per-IP detail in recon/ports/nmap/)"

# ================================================================ 4. summary
log "summary — open services by IP:"
[ -s recon/ports/services.txt ] && sed -n '1,40p' recon/ports/services.txt | sed 's/^/     /' >&2
# flag the juicy non-web services worth a manual look
JUICY='(^|[[:space:]])(21|22|23|25|111|135|139|389|445|873|1433|1521|2049|2375|2379|3000|3306|3389|5432|5601|5900|5984|5985|6379|6443|7001|8000|8080|8443|8500|9000|9090|9200|10250|11211|15672|27017)/'
log "non-web / sensitive services to check by hand (DB, RDP, SSH, Docker, Redis, Elastic, …):"
grep -hoE "$JUICY" recon/ports/services.txt 2>/dev/null | sort -u | sed 's/^/     port /' >&2 || true
sub "always confirm the service is really exposed + in scope before reporting. One PoC, no brute-force."
emit_report
ok "HTML report → recon/ports/report.html"
log "bb-ports done. Full output in $WORK/recon/ports/"
