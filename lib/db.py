#!/usr/bin/env python3
"""kestrel's workspace DB — a centralised, structured, queryable store of everything kestrel
collected on a target, in the spirit of Metasploit's db (hosts / services / vulns), but built
from kestrel's richer data (hosts with status, services, ports, CVEs, endpoints, and the triage
leads: secrets, params, admin panels, exposed services, ...).

The flat files under each program folder stay the source of truth; this db is a DERIVED store,
rebuilt any time by reading them (kestrel db sync). One shared SQLite file, default
~/hunts/kestrel.db, inspectable with the `sqlite3` CLI or any viewer.

    db.py <db> init
    db.py <db> sync <workdir> <program>
    db.py <db> stats
    db.py <db> view  <kind> <program|--all> [filters]   # hosts|services|ports|endpoints|vulns|leads
    db.py <db> host  <hostname> [program|--all]         # full dossier for one host
    db.py <db> ip    <address>  [program|--all]         # full dossier for one IP
    db.py <db> path  <substr>   [program|--all]         # every host exposing a matching path
    db.py <db> query "<sql>"
    db.py <db> shared-ips | shared-hosts

Filters for `view`:  -S <substr> (host) · -p <port> · -s <substr> (service) · --status <code>
                     -k <kind> (lead) · -m <substr> (url/value) · --live · --all

Entity views (host/ip/path) gather across ALL tables so one recall shows services, Shodan +
CVEs, endpoints (live/crawl/wayback) and leads for the entity, plus the host<->IP link.
"""
import ipaddress
import json
import os
import re
import sqlite3
import sys
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS programs(
  id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, first_seen TEXT, last_seen TEXT);
CREATE TABLE IF NOT EXISTS snapshots(
  id INTEGER PRIMARY KEY, program_id INTEGER, taken_at TEXT);
CREATE TABLE IF NOT EXISTS hosts(
  program_id INTEGER, host TEXT, live INTEGER DEFAULT 0, status INTEGER, info TEXT, last_seen TEXT,
  PRIMARY KEY(program_id, host));
CREATE TABLE IF NOT EXISTS ips(
  program_id INTEGER, ip TEXT, source TEXT, last_seen TEXT, PRIMARY KEY(program_id, ip));
CREATE TABLE IF NOT EXISTS host_ips(
  program_id INTEGER, host TEXT, ip TEXT, last_seen TEXT, PRIMARY KEY(program_id, host, ip));
CREATE TABLE IF NOT EXISTS ports(
  program_id INTEGER, ip TEXT, port INTEGER, service TEXT, version TEXT, source TEXT, last_seen TEXT,
  PRIMARY KEY(program_id, ip, port));
CREATE TABLE IF NOT EXISTS vulns(
  program_id INTEGER, ip TEXT, cve TEXT, last_seen TEXT, PRIMARY KEY(program_id, ip, cve));
CREATE TABLE IF NOT EXISTS endpoints(
  program_id INTEGER, url TEXT, host TEXT, status INTEGER, source TEXT, last_seen TEXT,
  PRIMARY KEY(program_id, url));
CREATE TABLE IF NOT EXISTS leads(
  program_id INTEGER, kind TEXT, value TEXT, host TEXT, last_seen TEXT,
  PRIMARY KEY(program_id, kind, value));
CREATE INDEX IF NOT EXISTS i_ips_ip   ON ips(ip);
CREATE INDEX IF NOT EXISTS i_hosts_h  ON hosts(host);
CREATE INDEX IF NOT EXISTS i_ports_ip ON ports(ip);
CREATE INDEX IF NOT EXISTS i_hostips_h ON host_ips(host);
CREATE INDEX IF NOT EXISTS i_hostips_ip ON host_ips(ip);
CREATE INDEX IF NOT EXISTS i_ep_host  ON endpoints(host);
"""

LEAD_FILES = {
    "api_open.txt": ("api_open", False), "fuzz_juicy.txt": ("fuzz_juicy", True),
    "js_secrets.txt": ("js_secret", True), "admin_panels.txt": ("admin", False),
    "exposed_services.txt": ("exposed_service", False), "code_hosts.txt": ("code_host", False),
    "js_endpoints.txt": ("js_endpoint", True), "params.txt": ("param", True),
    "js_uuids.txt": ("uuid", True), "wayback_interesting.txt": ("wayback", False),
}


def lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.rstrip("\n") for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def host_of(line):
    s = line.split()[0] if line.split() else line
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0]
    if s.count(":") == 1:
        s = s.split(":")[0]
    return s.strip().lower().strip(".")


def parse_live(line):
    """httpx live.txt line -> (host, status, info). Brackets are [status] [title] [tech]..."""
    host = host_of(line)
    br = re.findall(r"\[([^\]]*)\]", line)
    status = None
    rest = []
    for g in br:
        if status is None and re.fullmatch(r"\d{3}", g.strip()):
            status = int(g.strip())
        elif g.strip():
            rest.append(g.strip())
    return host, status, " · ".join(rest)


def registrable(host):
    parts = host.split(".")
    if len(parts) < 3:
        return host
    two = {"co", "com", "org", "net", "gov", "edu", "ac"}
    if parts[-2] in two and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def connect(db_path):
    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)
    return con


def get_program(con, name):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    con.execute("INSERT INTO programs(name, first_seen, last_seen) VALUES(?,?,?) "
                "ON CONFLICT(name) DO UPDATE SET last_seen=excluded.last_seen", (name, now, now))
    return con.execute("SELECT id FROM programs WHERE name=?", (name,)).fetchone()[0]


def _upsert_port(con, pid, ip, port, service, version, source, now):
    try:
        port = int(port)
        ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return
    con.execute(
        "INSERT INTO ports(program_id, ip, port, service, version, source, last_seen) "
        "VALUES(?,?,?,?,?,?,?) ON CONFLICT(program_id, ip, port) DO UPDATE SET "
        "service=CASE WHEN excluded.service<>'' THEN excluded.service ELSE ports.service END, "
        "version=CASE WHEN excluded.version<>'' THEN excluded.version ELSE ports.version END, "
        "last_seen=excluded.last_seen", (pid, ip, port, service, version, source, now))


def sync(con, work, program):
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    pid = get_program(con, program)
    con.execute("INSERT INTO snapshots(program_id, taken_at) VALUES(?,?)", (pid, now))
    recon = os.path.join(work, "recon")
    R = lambda *p: os.path.join(recon, *p)
    counts = {}

    # hosts (live.txt carries status + annotations; the broader sets fill in not-live hosts)
    live = {}
    for l in lines(R("live.txt")):
        h, st, info = parse_live(l)
        if h:
            live[h] = (st, info)
    others = set()
    for f in ("subs_inscope.txt", "hosts.txt", "surface_ok.txt"):
        for l in lines(R(f)):
            others.add(host_of(l))
    allh = set(live) | {h for h in others if h}
    for h in sorted(allh):
        st, info = live.get(h, (None, ""))
        con.execute("INSERT INTO hosts(program_id, host, live, status, info, last_seen) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(program_id, host) DO UPDATE SET live=max(hosts.live, excluded.live), "
                    "status=COALESCE(excluded.status, hosts.status), "
                    "info=CASE WHEN excluded.info<>'' THEN excluded.info ELSE hosts.info END, "
                    "last_seen=excluded.last_seen", (pid, h, 1 if h in live else 0, st, info, now))
    counts["hosts"] = len(allh)

    # ips
    ipset = {}
    for l in lines(R("ports", "ips.txt")):
        ipset.setdefault(l.strip(), "ports")
    for l in lines(R("ports", "naabu.txt")):
        ipset.setdefault(l.split(":")[0].strip(), "ports")
    for l in lines(R("ports", "shodan.jsonl")):
        try:
            ipset.setdefault(json.loads(l).get("ip", ""), "shodan")
        except ValueError:
            pass
    for ip, src in ipset.items():
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        con.execute("INSERT INTO ips(program_id, ip, source, last_seen) VALUES(?,?,?,?) "
                    "ON CONFLICT(program_id, ip) DO UPDATE SET last_seen=excluded.last_seen", (pid, ip, src, now))
    counts["ips"] = sum(1 for ip in ipset if _is_ip(ip))

    # ports + vulns
    nports = nvulns = 0
    for l in lines(R("ports", "services.txt")):
        parts = l.split()
        if len(parts) >= 2 and "/" in parts[1]:
            _upsert_port(con, pid, parts[0], parts[1].split("/")[0],
                         parts[3] if len(parts) > 3 else "",
                         " ".join(parts[4:]) if len(parts) > 4 else "", "active", now); nports += 1
    for l in lines(R("ports", "naabu.txt")):
        if ":" in l:
            ip, port = l.split(":", 1)
            _upsert_port(con, pid, ip.strip(), port.strip(), "", "", "active", now); nports += 1
    for l in lines(R("ports", "shodan.jsonl")):
        try:
            d = json.loads(l)
        except ValueError:
            continue
        ip = d.get("ip", "")
        for port in d.get("ports", []):
            _upsert_port(con, pid, ip, port, "", "", "shodan", now); nports += 1
        for cve in d.get("vulns", []):
            if _is_ip(ip):
                con.execute("INSERT OR IGNORE INTO vulns(program_id, ip, cve, last_seen) VALUES(?,?,?,?)",
                            (pid, ip, cve, now)); nvulns += 1
    counts["ports"] = nports
    counts["vulns"] = nvulns

    # host <-> IP map: the shodan step writes the resolution of every owned host, and the port
    # scan records which IPs httpx reached. This is what lets the db answer "does this IP already
    # belong to a host I've browsed?" and show every host that resolves to an IP.
    nhi = 0
    hi_pairs = set()
    for l in lines(R("ports", "host_ip_map.txt")):
        if "\t" in l:
            h, ip = l.split("\t", 1)
            hi_pairs.add((host_of(h), ip.strip()))
    for l in lines(R("ports", "_httpx_ip.txt")):          # optional: host<TAB>ip from httpx -ip
        if "\t" in l:
            h, ip = l.split("\t", 1)
            hi_pairs.add((host_of(h), ip.strip()))
    for h, ip in hi_pairs:
        if h and _is_ip(ip):
            con.execute("INSERT INTO host_ips(program_id, host, ip, last_seen) VALUES(?,?,?,?) "
                        "ON CONFLICT(program_id, host, ip) DO UPDATE SET last_seen=excluded.last_seen",
                        (pid, h, ip, now)); nhi += 1
    counts["host_ips"] = nhi

    # endpoints (multi-source: live probe, crawl, wayback archive) — each carries its host so an
    # entity view can gather every URL ever seen for a host, whatever found it.
    ne = 0
    def add_ep(url, status, source):
        nonlocal ne
        url = url.strip()
        if "://" not in url:
            return
        con.execute("INSERT INTO endpoints(program_id, url, host, status, source, last_seen) VALUES(?,?,?,?,?,?) "
                    "ON CONFLICT(program_id, url) DO UPDATE SET "
                    "status=COALESCE(excluded.status, endpoints.status), "
                    "host=CASE WHEN excluded.host<>'' THEN excluded.host ELSE endpoints.host END, "
                    "last_seen=excluded.last_seen", (pid, url, host_of(url), status, source, now))
        ne += 1
    for l in lines(R("live.txt")):
        parts = l.split()
        if parts and "://" in parts[0]:
            m = re.search(r"\[(\d{3})\]", l)
            add_ep(parts[0], int(m.group(1)) if m else None, "live")
    for f in ("js/_urls.txt", "js/urls.txt"):             # katana / crawl output (whichever exists)
        for l in lines(R(f)):
            add_ep(l.split()[0] if l.split() else l, None, "crawl")
    for l in lines(R("wayback", "urls.txt")):
        add_ep(l, None, "wayback")
    counts["endpoints"] = ne

    # leads (triage buckets + shodan ports)
    tri = os.path.join(recon, "triage")
    nl = 0
    for fname, (kind, has_host) in LEAD_FILES.items():
        for l in lines(os.path.join(tri, fname)):
            if has_host and "\t" in l:
                value, host = l.split("\t", 1)
                host = host.split(",")[0].strip()
            else:
                value, host = l, ""
            con.execute("INSERT INTO leads(program_id, kind, value, host, last_seen) VALUES(?,?,?,?,?) "
                        "ON CONFLICT(program_id, kind, value) DO UPDATE SET last_seen=excluded.last_seen",
                        (pid, kind, value.strip(), host, now)); nl += 1
    for l in lines(os.path.join(tri, "shodan_ports.txt")):
        con.execute("INSERT INTO leads(program_id, kind, value, host, last_seen) VALUES(?,?,?,?,?) "
                    "ON CONFLICT(program_id, kind, value) DO UPDATE SET last_seen=excluded.last_seen",
                    (pid, "shodan", l.strip(), l.split("\t")[0].strip(), now)); nl += 1
    counts["leads"] = nl

    con.commit()
    return counts


def _is_ip(x):
    try:
        ipaddress.ip_address(x); return True
    except ValueError:
        return False


def print_rows(rows, header=None):
    if header:
        print("\t".join(header))
    for r in rows:
        print("\t".join("" if c is None else str(c) for c in r))


def view(con, kind, program, args):
    """Metasploit-style recall. program = name, or '--all' / '-' for every program."""
    allp = program in ("--all", "-") or "--all" in args
    # parse filters
    f = {}
    it = iter(args)
    for a in it:
        if a == "-S": f["S"] = next(it, "")
        elif a == "-p": f["p"] = next(it, "")
        elif a == "-s": f["s"] = next(it, "")
        elif a == "--status": f["status"] = next(it, "")
        elif a == "-k": f["k"] = next(it, "")
        elif a == "-m": f["m"] = next(it, "")
        elif a == "--live": f["live"] = True
        elif a == "--all": pass
        else: pass

    where, params = [], []
    if not allp:
        row = con.execute("SELECT id FROM programs WHERE name=?", (program,)).fetchone()
        if not row:
            print(f"program '{program}' not in db — run: kestrel db sync {program}", file=sys.stderr)
            return 3
        where.append("t.program_id=?"); params.append(row[0])
    progcol = "p.name AS program, " if allp else ""
    progjoin = "JOIN programs p ON p.id=t.program_id" if allp else ""

    if kind == "hosts":
        cols = f"{progcol}t.host, t.status, t.live, t.info"
        if "S" in f: where.append("t.host LIKE ?"); params.append(f"%{f['S']}%")
        if f.get("live"): where.append("t.live=1")
        order = "t.host"
    elif kind in ("services", "ports"):
        cols = f"{progcol}t.ip, t.port, t.service, t.version, t.source" if kind == "services" \
               else f"{progcol}t.ip, t.port, t.source"
        if "p" in f: where.append("t.port=?"); params.append(f["p"])
        if "s" in f: where.append("t.service LIKE ?"); params.append(f"%{f['s']}%")
        order = "t.ip, t.port"
        kind = "ports"      # table name
    elif kind == "vulns":
        cols = f"{progcol}t.ip, t.cve"
        order = "t.ip, t.cve"
    elif kind == "endpoints":
        cols = f"{progcol}t.url, t.status"
        if "status" in f: where.append("t.status=?"); params.append(f["status"])
        if "m" in f: where.append("t.url LIKE ?"); params.append(f"%{f['m']}%")
        order = "t.url"
    elif kind == "leads":
        cols = f"{progcol}t.kind, t.value, t.host"
        if "k" in f: where.append("t.kind=?"); params.append(f["k"])
        if "m" in f: where.append("t.value LIKE ?"); params.append(f"%{f['m']}%")
        order = "t.kind, t.value"
    else:
        print(f"unknown view '{kind}'", file=sys.stderr); return 2

    sql = f"SELECT {cols} FROM {kind} t {progjoin}"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += f" ORDER BY {order}"
    cur = con.execute(sql, params)
    print_rows(cur.fetchall(), [d[0] for d in cur.description])
    return 0


def _section(title, rows, header):
    """Print one labelled block of an entity dossier; silent when there's nothing."""
    if not rows:
        return
    print(f"\n# {title}")
    print_rows(rows, header)


def entity_host(con, name, allp):
    """Everything the db holds about one hostname: resolutions, services on those IPs,
    Shodan, CVEs, endpoints (live/crawl/wayback), leads attributed to it."""
    name = name.strip().lower().strip(".")
    pfilter = "" if allp else " AND program_id=(SELECT id FROM programs WHERE name=?)"
    # which program(s) is this host in — resolve a single pid for the non-all case
    pid = None
    if not allp:
        r = con.execute("SELECT DISTINCT program_id FROM hosts WHERE host=?", (name,)).fetchone() \
            or con.execute("SELECT DISTINCT program_id FROM host_ips WHERE host=?", (name,)).fetchone()
        pid = r[0] if r else None
    pp = [] if allp else [pid]

    hdr = con.execute(f"SELECT host, live, status, info FROM hosts WHERE host=?"
                      + ("" if allp else " AND program_id=?"), [name] + pp).fetchall()
    _section("host", hdr, ["host", "live", "status", "info"])

    ips = [r[0] for r in con.execute(
        f"SELECT DISTINCT ip FROM host_ips WHERE host=?" + ("" if allp else " AND program_id=?"),
        [name] + pp).fetchall()]
    _section("resolves to", [(ip,) for ip in ips], ["ip"])

    if ips:
        q = ",".join("?" * len(ips))
        _section("services", con.execute(
            f"SELECT ip, port, service, version, source FROM ports WHERE ip IN ({q})"
            + ("" if allp else " AND program_id=?") + " ORDER BY ip, port",
            ips + pp).fetchall(), ["ip", "port", "service", "version", "source"])
        _section("shodan CVEs", con.execute(
            f"SELECT ip, cve FROM vulns WHERE ip IN ({q})"
            + ("" if allp else " AND program_id=?") + " ORDER BY ip, cve",
            ips + pp).fetchall(), ["ip", "cve"])

    _section("endpoints", con.execute(
        f"SELECT source, status, url FROM endpoints WHERE host=?"
        + ("" if allp else " AND program_id=?") + " ORDER BY source, url",
        [name] + pp).fetchall(), ["source", "status", "url"])

    _section("leads", con.execute(
        f"SELECT kind, value FROM leads WHERE host=?"
        + ("" if allp else " AND program_id=?") + " ORDER BY kind, value",
        [name] + pp).fetchall(), ["kind", "value"])
    return 0


def entity_ip(con, addr, allp):
    """Everything about one IP: owning host(s), services/ports, Shodan CVEs."""
    addr = addr.strip()
    pid = None
    if not allp:
        r = con.execute("SELECT DISTINCT program_id FROM ips WHERE ip=?", (addr,)).fetchone() \
            or con.execute("SELECT DISTINCT program_id FROM ports WHERE ip=?", (addr,)).fetchone() \
            or con.execute("SELECT DISTINCT program_id FROM host_ips WHERE ip=?", (addr,)).fetchone()
        pid = r[0] if r else None
    pp = [] if allp else [pid]

    _section("ip", con.execute(
        f"SELECT ip, source FROM ips WHERE ip=?" + ("" if allp else " AND program_id=?"),
        [addr] + pp).fetchall(), ["ip", "source"])

    hosts = con.execute(
        f"SELECT DISTINCT host FROM host_ips WHERE ip=?" + ("" if allp else " AND program_id=?")
        + " ORDER BY host", [addr] + pp).fetchall()
    _section("belongs to host(s)", hosts, ["host"])

    _section("services", con.execute(
        f"SELECT port, service, version, source FROM ports WHERE ip=?"
        + ("" if allp else " AND program_id=?") + " ORDER BY port",
        [addr] + pp).fetchall(), ["port", "service", "version", "source"])

    _section("shodan CVEs", con.execute(
        f"SELECT cve FROM vulns WHERE ip=?" + ("" if allp else " AND program_id=?") + " ORDER BY cve",
        [addr] + pp).fetchall(), ["cve"])
    return 0


def entity_path(con, substr, program, allp):
    """Pivot: every host that exposes a URL whose path matches <substr>."""
    substr = substr.strip()
    sql_ep = "SELECT DISTINCT host, url AS loc, source FROM endpoints WHERE url LIKE ?"
    pe = [f"%{substr}%"]
    if not allp:
        sql_ep += " AND program_id=(SELECT id FROM programs WHERE name=?)"; pe.append(program)
    sql_ep += " ORDER BY host, loc"
    _section(f"hosts exposing a path matching '{substr}'",
             con.execute(sql_ep, pe).fetchall(), ["host", "url", "source"])
    return 0


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    db_path, action = argv[1], argv[2]
    con = connect(db_path)
    rc = 0
    if action == "init":
        print(f"OK {db_path}")
    elif action == "sync":
        if len(argv) < 5:
            print("usage: db.py <db> sync <workdir> <program>", file=sys.stderr); return 2
        for k, v in sync(con, argv[3], argv[4]).items():
            print(f"{k.upper()}={v}")
    elif action == "stats":
        for tbl in ("programs", "hosts", "ips", "host_ips", "ports", "vulns", "endpoints", "leads"):
            print(f"{tbl.upper()}={con.execute(f'SELECT COUNT(*) FROM {tbl}').fetchone()[0]}")
    elif action == "view":
        if len(argv) < 5:
            print("usage: db.py <db> view <kind> <program|--all> [filters]", file=sys.stderr); return 2
        rc = view(con, argv[3], argv[4], argv[5:])
    elif action in ("host", "ip", "path"):
        if len(argv) < 4:
            print(f"usage: db.py <db> {action} <value> [program|--all]", file=sys.stderr); return 2
        value = argv[3]
        program = argv[4] if len(argv) > 4 else "--all"
        allp = program in ("--all", "-")
        if action == "host":
            rc = entity_host(con, value, allp)
        elif action == "ip":
            rc = entity_ip(con, value, allp)
        else:
            rc = entity_path(con, value, program, allp)
    elif action == "query":
        if len(argv) < 4:
            print("usage: db.py <db> query \"<sql>\"", file=sys.stderr); return 2
        cur = con.execute(argv[3])
        print_rows(cur.fetchall(), [d[0] for d in cur.description] if cur.description else None)
    elif action == "shared-ips":
        cur = con.execute(
            "SELECT i.ip, COUNT(DISTINCT i.program_id) n, GROUP_CONCAT(DISTINCT p.name) "
            "FROM ips i JOIN programs p ON p.id=i.program_id GROUP BY i.ip HAVING n>1 ORDER BY n DESC, i.ip")
        print_rows(cur.fetchall(), ["ip", "programs", "names"])
    elif action == "shared-hosts":
        names = dict(con.execute("SELECT id, name FROM programs").fetchall())
        reg = {}
        for host, pid in con.execute("SELECT host, program_id FROM hosts").fetchall():
            reg.setdefault(registrable(host), set()).add(pid)
        out = [(d, len(ps), ",".join(sorted(names.get(p, str(p)) for p in ps)))
               for d, ps in reg.items() if len(ps) > 1]
        print_rows(sorted(out, key=lambda x: -x[1]), ["domain", "programs", "names"])
    else:
        print(f"unknown action '{action}'", file=sys.stderr); rc = 2
    con.close()
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
