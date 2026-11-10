#!/usr/bin/env python3
"""Offline triage: parse what recon/ports/fuzz/js already collected into categorised leads.

    triage.py <workdir>

ZERO network. Reads only files already on disk (recon/, content/, js/) and sorts them into
lead files under recon/triage/. Prints KEY=COUNT lines. Nothing here sends a request: turning a
path found in a JS bundle into a confirmed endpoint is still a manual, minimal-touch step.

Writes recon/triage/:
  api_open.txt        JSON 200 endpoints (open) — from api_json.txt + ffuf
  api_gated.txt       API paths behind 401/403 (the surface, not a finding)
  api_paths.txt       safety net: anything whose path looks like an API, any status
  fuzz_real.txt       ffuf 200s with a real body, walls (repeated size) dropped
  fuzz_juicy.txt      ffuf 200s on sensitive paths (.git/.env/actuator/backup/...)
  js_endpoints.txt    routes/endpoints mined from the JS bundles, with the host(s) they came from
  js_secrets.txt      secret/key-looking strings in the JS bundles
  js_uuids.txt        real UUIDs in the JS bundles (nil/RFC examples dropped), with their host(s)
  js_urls.txt         crawl URLs (js/_urls.txt) that look interesting
  robots_nonstd.txt   robots/sitemap paths minus the usual noise
  admin_panels.txt    admin/login/console surfaces
  code_hosts.txt      git/CI hosts (gitlab/jenkins/...)
  exposed_services.txt dashboards/brokers (grafana/kibana/rabbitmq/...)
  shodan_ports.txt    IP -> open ports (+ CVE count) from passive Shodan (kestrel shodan)
  catchall.txt        catch-all hosts to keep OUT of the leads (reference)
"""
import glob
import json
import os
import re
import sys


def lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.rstrip("\n") for l in fh if l.strip()]
    except OSError:
        return []


def write(path, rows):
    rows = list(dict.fromkeys(r for r in rows if r and r.strip()))  # de-dup, keep order
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(rows) + ("\n" if rows else ""))
    return len(rows)


def host_of(s):
    """Best-effort hostname from a URL or an httpx line ('https://h [200] ...')."""
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s.strip(), flags=re.I)
    s = re.split(r"[/\s\[]", s, maxsplit=1)[0].split("@")[-1]
    if s.count(":") == 1:
        s = s.split(":")[0]
    return s.lower()


def host_of_file(f, js_root):
    """The <host> dir a JS bundle sits under: js/<host>/<hash>.js → '<host>' (else '')."""
    parts = os.path.relpath(f, js_root).split(os.sep)
    return parts[0] if len(parts) > 1 else ""


def fmt_hosts(hosts, cap=6):
    """Sorted, comma-joined host list, truncated with '+N' past the cap."""
    hs = sorted(h for h in hosts if h)
    if not hs:
        return ""
    return ", ".join(hs[:cap]) + (f" +{len(hs) - cap}" if len(hs) > cap else "")


def ffuf_results(w):
    """Yield (host, status, length, ctype, url) from every content/ffuf_*.json."""
    for f in sorted(glob.glob(os.path.join(w, "content", "ffuf_*.json"))):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        for x in data.get("results", []):
            yield (x.get("host") or "", x.get("status") or 0,
                   x.get("length") or 0, (x.get("content-type") or ""),
                   x.get("url") or "")


JUICY = re.compile(
    r"(\.git|\.env|actuator|swagger|api-docs|openapi|graphql|backup|\.sql|dump|"
    r"config\.(json|php|ya?ml)|\.bak|/admin|phpinfo|WEB-INF|\.svn|\.DS_Store|heapdump)",
    re.I)
API_PATH = re.compile(r"/(health|version|status|api|graphql|rest|openapi|swagger|v[0-9]+)([/?]|$)", re.I)
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)
UUID_SKIP = re.compile(r"^(00000000-0000|6ba7b81[01]-9dad-11d1-80b4)", re.I)
# A real leaked SECRET is a credential VALUE, not a variable name. Matching the bare words
# "secret"/"token"/"client_secret" floods on library source (React __SECRET_INTERNALS…, AntD
# SECRET_COMBOBOX_MODE, oidc-client's client_secret/access_token identifiers). So match only:
#   1. known high-signal token formats (AWS/Google/Slack/GitHub/JWT/private key), and
#   2. a secret-ish KEY assigned a quoted, long, high-entropy literal.
SECRET_TOKEN = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}"                  # AWS
    r"|AIza[0-9A-Za-z_\-]{20,}|ya29\.[0-9A-Za-z_\-]{20,}"  # Google
    r"|xox[baprs]-[0-9A-Za-z-]{10,}"                       # Slack
    r"|gh[pousr]_[0-9A-Za-z]{30,}"                         # GitHub
    r"|sk-[0-9A-Za-z]{20,}"                                # OpenAI-style
    r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"  # JWT
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)")
SECRET_ASSIGN = re.compile(
    r"""(?i)(api[_-]?key|secret[_-]?key|client[_-]?secret|access[_-]?key|auth[_-]?token"""
    r"""|private[_-]?key|passwd|password)\s*[:=]\s*["']([A-Za-z0-9+/_\-]{16,})["']""")
SECRET_DENY = re.compile(
    r"DO_NOT_USE|DO_NOT_PASS|__SECRET_INTERNALS|COMBOBOX_MODE|BE_FIRED|"
    r"example|placeholder|xxxx|your[_-]?(api|secret|token|key)|undefined|null", re.I)
JS_ENDPOINT = re.compile(r'["\'](/[A-Za-z0-9_/.?=-]{3,})["\']')
JS_ENDPOINT_KEEP = re.compile(r"(api|v[0-9]|graphql|admin|token|user|upload|internal|auth|secret|key)", re.I)
JS_ENDPOINT_DROP = re.compile(r"/(src|node_modules|locales|assets)/|\.(png|svg|css|map|json|woff2?|ico|jpe?g|gif)$", re.I)
# parameter names — a fuzzing wordlist built offline from URLs and JS.
# {0,39} (not {1,}) so single-letter params are kept: s/q/p are real XSS/SQLi/IDOR surfaces.
QUERY_PARAM = re.compile(r"[?&]([A-Za-z_][\w\-]{0,39})=")
JS_PARAM = re.compile(
    r"""(?:searchParams\.get|getParameter|\.get)\(["']([A-Za-z_][\w\-]{0,39})["']\)"""
    r"""|(?:req|request|ctx)\.(?:query|params|body)\.([A-Za-z_]\w{0,39})""")
PARAM_DROP = re.compile(r"^(utm_\w*|fbclid|gclid|_ga\w*|cb|callback|jsonp)$", re.I)


def api_leads(w):
    """open (JSON 200), gated (401/403 JSON + quickhits_auth), path-based safety net."""
    openj, gated, paths = [], [], []
    # source 1: recon/api_json.txt — "code size url", all 200 JSON already vetted
    for l in lines(os.path.join(w, "recon/api_json.txt")):
        p = l.split()
        if len(p) >= 3:
            openj.append(f"{p[0]}\t{p[1]}\t{p[2]}")
    # source 2: ffuf raw, by content-type and by path
    for host, st, ln, ct, url in ffuf_results(w):
        is_json = "json" in ct.lower() and "html" not in ct.lower()
        if st == 200 and is_json:
            openj.append(f"200\t{ln}\t{url}")
        elif st in (401, 403) and is_json:
            gated.append(f"{st}\t{url}")
        if API_PATH.search(url):
            paths.append(f"{st}\t{url}")
    # gated API-ish paths from quickhits_auth
    for l in lines(os.path.join(w, "recon/quickhits_auth.txt")):
        if re.search(r"/api|/graphql|/rest|/v[0-9]", l, re.I):
            gated.append(l)
    return openj, gated, paths


def fuzz_leads(w):
    """200s with a real body (walls dropped) + sensitive-path 200s."""
    per_host = {}
    for host, st, ln, ct, url in ffuf_results(w):
        if st == 200:
            per_host.setdefault(host, []).append((ln, url))
    real, juicy = [], []
    for host, items in per_host.items():
        counts = {}
        for ln, _ in items:
            counts[ln] = counts.get(ln, 0) + 1
        for ln, url in items:
            if counts[ln] < 3:          # not a wall (a repeated size >=3 is a blanket response)
                real.append(f"{host}\t{ln}\t{url}")
            if JUICY.search(url):
                juicy.append(f"{host}\t{url}")
    return real, juicy


def js_leads(w):
    # route/uuid → set(hosts): each is attributed to the js/<host>/ bundle it was mined from.
    endpoints, secrets, uuids = {}, [], {}
    js_root = os.path.join(w, "js")
    for f in glob.glob(os.path.join(w, "js", "**", "*.js"), recursive=True):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        rel = os.path.relpath(f, w)
        host = host_of_file(f, js_root)
        for m in JS_ENDPOINT.findall(text):
            if JS_ENDPOINT_KEEP.search(m) and not JS_ENDPOINT_DROP.search(m):
                endpoints.setdefault(m, set()).add(host)
        for m in SECRET_TOKEN.finditer(text):
            ctx = text[max(0, m.start() - 10):m.end() + 10].replace("\n", " ")
            if not SECRET_DENY.search(ctx):
                secrets.append(f"{rel}\t{m.group(0)[:60]}")
        for m in SECRET_ASSIGN.finditer(text):
            val = m.group(2)
            if SECRET_DENY.search(m.group(0)) or len(set(val)) < 6:
                continue  # library identifier / placeholder / low-entropy, not a real secret
            secrets.append(f"{rel}\t{m.group(1)}={val[:48]}")
        for m in UUID.findall(text):
            if not UUID_SKIP.match(m):
                uuids.setdefault(m, set()).add(host)
    urls = [u for u in lines(os.path.join(w, "js/_urls.txt"))
            if re.search(r"api|admin|token|upload|\.json", u, re.I)]
    ep_rows = [f"{route}\t{fmt_hosts(hosts)}" for route, hosts in sorted(endpoints.items())]
    uuid_rows = [f"{u}\t{fmt_hosts(hosts)}" for u, hosts in sorted(uuids.items())]
    return ep_rows, secrets, uuid_rows, urls


def param_leads(w):
    """Parameter names mined offline from every URL we have + the JS bundles — a fuzz wordlist,
    each attributed to the host(s) it was seen on so you know where to try it (IDOR on id, XSS/SQLi
    on s, …)."""
    params = {}  # name -> set(hosts)

    def add(name, host):
        if name and not PARAM_DROP.match(name):
            params.setdefault(name, set()).add(host or "")

    url_sources = ["js/_urls.txt", "recon/sitemap_urls.txt", "recon/robots_urls.txt",
                   "recon/surface_ok.txt", "recon/quickhits.txt"]
    for name in url_sources:
        for l in lines(os.path.join(w, name)):
            h = host_of(l)
            for m in QUERY_PARAM.findall(l):
                add(m, h)
    for l in lines(os.path.join(w, "recon/api_json.txt")):
        p = l.split()
        if len(p) >= 3:
            h = host_of(p[2])
            for m in QUERY_PARAM.findall(p[2]):
                add(m, h)
    for host, _, _, _, url in ffuf_results(w):
        for m in QUERY_PARAM.findall(url):
            add(m, host or host_of(url))
    js_root = os.path.join(w, "js")
    for f in glob.glob(os.path.join(w, "js", "**", "*.js"), recursive=True):
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        host = host_of_file(f, js_root)
        for m in QUERY_PARAM.findall(text):
            add(m, host)
        for a, b in JS_PARAM.findall(text):
            add(a or b, host)
    return [f"{name}\t{fmt_hosts(hosts)}" for name, hosts in sorted(params.items())]


def grep_lines(src_lines, pattern):
    rx = re.compile(pattern, re.I)
    return [l for l in src_lines if rx.search(l)]


def main(w):
    out = os.path.join(w, "recon/triage")
    os.makedirs(out, exist_ok=True)

    openj, gated, apaths = api_leads(w)
    real, juicy = fuzz_leads(w)
    js_ep, js_sec, js_uuid, js_url = js_leads(w)
    live = lines(os.path.join(w, "recon/live.txt"))
    surface = lines(os.path.join(w, "recon/surface_ok.txt"))
    robots = lines(os.path.join(w, "recon/robots_urls.txt")) + lines(os.path.join(w, "recon/robots_targets.txt"))

    counts = {}
    counts["API_OPEN"] = write(os.path.join(out, "api_open.txt"), openj)
    counts["API_GATED"] = write(os.path.join(out, "api_gated.txt"), gated)
    counts["API_PATHS"] = write(os.path.join(out, "api_paths.txt"), apaths)
    counts["FUZZ_REAL"] = write(os.path.join(out, "fuzz_real.txt"), real)
    counts["FUZZ_JUICY"] = write(os.path.join(out, "fuzz_juicy.txt"), juicy)
    params_rows = param_leads(w)
    counts["JS_ENDPOINTS"] = write(os.path.join(out, "js_endpoints.txt"), js_ep)
    counts["JS_SECRETS"] = write(os.path.join(out, "js_secrets.txt"), js_sec)
    counts["JS_UUIDS"] = write(os.path.join(out, "js_uuids.txt"), js_uuid)
    counts["JS_URLS"] = write(os.path.join(out, "js_urls.txt"), js_url)
    counts["PARAMS"] = write(os.path.join(out, "params.txt"), params_rows)
    # plain, host-less wordlists (first column only) — ready to fuzz across the program's other hosts
    plain = lambda rows: [r.split("\t", 1)[0] for r in rows]
    write(os.path.join(out, "paths_fuzz.txt"), plain(js_ep))
    write(os.path.join(out, "params_fuzz.txt"), plain(params_rows))
    counts["ROBOTS_NONSTD"] = write(os.path.join(out, "robots_nonstd.txt"),
        [l for l in robots if not re.search(
            r"README|LICENSE|/admin/?$|composer|/modules/|/themes/|/sites/|/core/", l, re.I)])
    counts["ADMIN_PANELS"] = write(os.path.join(out, "admin_panels.txt"),
        grep_lines(surface, r"admin|login|logout|dashboard|console|portal|signin|auth"))
    counts["CODE_HOSTS"] = write(os.path.join(out, "code_hosts.txt"),
        grep_lines(live, r"gitlab|gitea|jenkins|bitbucket|(^|[^a-z])git\."))
    counts["EXPOSED_SERVICES"] = write(os.path.join(out, "exposed_services.txt"),
        grep_lines(live, r"kibana|grafana|elastic|activemq|rabbitmq|consul|phpmyadmin|solr|kong|minio|airflow"))
    # passive Shodan findings (third-party IPs are already excluded by kestrel shodan)
    shodan_rows = []
    for line in lines(os.path.join(w, "recon/ports/shodan.jsonl")):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        ip = d.get("ip", "")
        ports = ",".join(str(p) for p in d.get("ports", []))
        ncve = len(d.get("vulns", []))
        if ip and ports:
            shodan_rows.append(f"{ip}\t{ports}" + (f"\tCVEs={ncve}" if ncve else ""))
    counts["SHODAN"] = write(os.path.join(out, "shodan_ports.txt"), shodan_rows)
    counts["CATCHALL"] = write(os.path.join(out, "catchall.txt"),
        lines(os.path.join(w, "recon/surface_catchall.txt")))

    for k, v in counts.items():
        print(f"{k}={v}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
