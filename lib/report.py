#!/usr/bin/env python3
"""kestrel report — one self-contained HTML page per program, from whatever files exist.

    report.py <workdir> <out.html>

Reads the program folder and renders only the sections that have data:
  header   program, platform, URL, scope, last runs
  recon    funnel + leads
  fuzz     ffuf results per host (real sizes first, WAF walls collapsed)
  ports    Shodan InternetDB (passive) + naabu/nmap services (active), labelled
  secrets  trufflehog verified findings (masked) + code-search leads
  retest   per-run history: new / live / gone, newest first

No traffic, no tools: it only reads files. Safe to run any time.
"""
import glob
import html
import json
import os
import sys
import time

CSS = """
body{margin:0;background:#0d1117;color:#c9d1d9;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1100px;margin:0 auto;padding:24px 16px}
h1{font-size:22px;margin:0 0 4px}
.subt{color:#8b949e;margin-bottom:8px;font-size:13px;word-break:break-all}
.meta{color:#8b949e;font-size:13px;margin:2px 0}
h2{font-size:16px;border-bottom:1px solid #21262d;padding-bottom:6px;margin:32px 0 8px}
nav{margin:14px 0 4px;position:sticky;top:0;background:#0d1117;padding:8px 0;border-bottom:1px solid #21262d}
nav a{margin-right:16px;font-size:13px}
.cards{display:flex;flex-wrap:wrap;gap:10px;margin:12px 0}
.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:10px 14px;min-width:84px}
.card .n{font-size:20px;font-weight:600;color:#e6edf3}
.card .l{font-size:11px;color:#8b949e;text-transform:uppercase;letter-spacing:.04em}
table{border-collapse:collapse;width:100%;margin:6px 0 14px;font-family:ui-monospace,monospace;font-size:13px}
td,th{padding:3px 8px;border-bottom:1px solid #1b2128;text-align:left;vertical-align:top}
th{color:#8b949e;font-weight:600;border-bottom:1px solid #21262d}
td.u{word-break:break-all}td.num{text-align:right;color:#8b949e;white-space:nowrap}
code{color:#e6edf3}
.tag{display:inline-block;background:#21262d;border-radius:4px;padding:0 6px;margin:0 3px 2px 0;font-size:12px}
.tag.p{background:#1f6feb33;color:#79c0ff}.tag.v{background:#da363322;color:#ff7b72}
.muted{color:#8b949e}.empty{color:#6e7681;font-style:italic}
.pill{font-size:11px;padding:1px 7px;border-radius:10px;border:1px solid #30363d;color:#8b949e}
.pill.pass{border-color:#238636;color:#3fb950}.pill.act{border-color:#9e6a03;color:#d29922}
details{margin:6px 0}summary{cursor:pointer;color:#8b949e}
h3.host{font-size:13px;color:#e6edf3;margin:14px 0 4px;font-family:ui-monospace,monospace}
"""


def esc(s):
    return html.escape(str(s))


def read_lines(path, cap=0):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            out = [l.rstrip("\n") for l in fh if l.strip()]
    except OSError:
        return []
    return out[:cap] if cap else out


def n_lines(path):
    return len(read_lines(path))


class R:
    def __init__(self):
        self.h = []

    def __iadd__(self, s):
        self.h.append(s)
        return self

    def table(self, headers, rows, cap=200):
        if not rows:
            return
        self += "<table><tr>" + "".join(f"<th>{esc(x)}</th>" for x in headers) + "</tr>"
        for r in rows[:cap]:
            self += "<tr>" + "".join(f"<td class=u>{c}</td>" for c in r) + "</tr>"
        self += "</table>"
        if len(rows) > cap:
            self += f"<p class=muted>… +{len(rows)-cap} more in the source file</p>"


def section_recon(w, r, nav):
    live = os.path.join(w, "recon/live.txt")
    if not os.path.exists(live):
        return
    nav.append(("recon", "Recon"))
    r += "<h2 id=recon>Recon</h2>"
    funnel = [
        ("subs_inscope.txt", "in scope"), ("resolved.txt", "resolving"),
        ("live.txt", "live"), ("surface.txt", "surface"),
        ("surface_ok.txt", "real"), ("surface_catchall.txt", "catch-all"),
    ]
    r += "<div class=cards>"
    for f, label in funnel:
        c = n_lines(os.path.join(w, "recon", f))
        r += f"<div class=card><div class=n>{c}</div><div class=l>{esc(label)}</div></div>"
    r += "</div>"

    leads = [
        ("api_json.txt", "APIs returning JSON 200"),
        ("quickhits_auth.txt", "401 / 403-gated paths"),
        ("quickhits_interesting.txt", "paths with an odd size"),
        ("rescued.txt", "root-404 hosts that speak"),
        ("browser_todo.txt", "walls to open by hand"),
        ("robots_targets.txt", "targets from robots.txt"),
    ]
    any_lead = False
    for f, label in leads:
        lines = read_lines(os.path.join(w, "recon", f))
        if not lines:
            continue
        any_lead = True
        r += f"<details><summary>{esc(label)} — {len(lines)}</summary>"
        r += "<table>" + "".join(f"<tr><td class=u><code>{esc(l)}</code></td></tr>" for l in lines[:300]) + "</table>"
        if len(lines) > 300:
            r += f"<p class=muted>… +{len(lines)-300} more</p>"
        r += "</details>"
    if not any_lead:
        r += "<p class=empty>No automatic leads — review the JS bundles under js/.</p>"



def section_fuzz(w, r, nav):
    files = sorted(glob.glob(os.path.join(w, "content/*.json")))
    hosts = []
    for f in files:
        try:
            with open(f, encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        results = data.get("results", [])
        if not results:
            continue
        sizes = {x.get("length") for x in results}
        all_html = all("html" in (x.get("content-type") or "") for x in results)
        host = results[0].get("host") or os.path.basename(f)
        # A WALL is a blanket response: every path answers with the same status and a
        # near-identical size (sizes differ only by the reflected path length, e.g. 1917 vs
        # 1918). That catches a WAF/SPA that 403s or 200s everything, even though the sizes
        # are not byte-identical — which an exact len(sizes)==1 test would miss.
        statuses = {x.get("status") for x in results}
        lengths = [x.get("length") for x in results if isinstance(x.get("length"), (int, float))]
        spread = (max(lengths) - min(lengths)) if lengths else 0
        if len(results) >= 3 and len(statuses) == 1 and spread <= 32:
            kind = "wall"
        elif len(sizes) > 1:
            kind = "real"
        elif all_html:
            kind = "html"
        else:
            kind = "single"
        hosts.append((kind, host, results))
    if not hosts:
        return
    nav.append(("fuzz", "Fuzz"))
    r += "<h2 id=fuzz>Fuzz (ffuf)</h2>"
    order = {"real": 0, "single": 1, "html": 2, "wall": 3}
    hosts.sort(key=lambda x: (order.get(x[0], 9), x[1]))
    real = sum(1 for k, _, _ in hosts if k == "real")
    walls = sum(1 for k, _, _ in hosts if k == "wall")
    r += f"<p class=muted>{len(hosts)} host(s) fuzzed · {real} with varying sizes (look first) · {walls} blanket walls (one response for every path, collapsed)</p>"
    badge = {"real": "🟢 real", "single": "🟡 single size", "html": "🟡 HTML/SPA", "wall": "🔴 wall"}
    for kind, host, results in hosts:
        if kind == "wall":
            st = next(iter({x.get("status") for x in results}), "?")
            lens = [x.get("length") for x in results if isinstance(x.get("length"), (int, float))]
            sz = min(lens) if lens else "?"
            r += f"<details><summary>{esc(host)} — 🔴 wall ({len(results)} paths, all status {esc(st)}, size ~{esc(sz)}) — one response for everything, likely WAF, ignore</summary>"
            r += "<table>" + "".join(f"<tr><td class=u><code>{esc(x.get('url',''))}</code></td></tr>" for x in results[:60]) + "</table></details>"
            continue
        r += f"<h3 class=host>{esc(host)} — {badge.get(kind, kind)}</h3>"
        rows = []
        for x in sorted(results, key=lambda y: (y.get("status", 0), y.get("url", "")))[:120]:
            ct = (x.get("content-type") or "-").split(";")[0]
            rows.append((str(x.get("status", "")), esc(ct), str(x.get("length", "")), f"<code>{esc(x.get('url',''))}</code>"))
        r += "<table><tr><th>status</th><th>type</th><th>size</th><th>url</th></tr>"
        for st, ct, sz, url in rows:
            r += f"<tr><td>{st}</td><td>{ct}</td><td class=num>{sz}</td><td class=u>{url}</td></tr>"
        r += "</table>"


def section_ports(w, r, nav):
    sh = os.path.join(w, "recon/ports/shodan.jsonl")
    services = os.path.join(w, "recon/ports/services.txt")
    if not os.path.exists(sh) and not os.path.exists(services):
        return
    nav.append(("ports", "Ports"))
    r += "<h2 id=ports>Ports &amp; services</h2>"

    recs = []
    for line in read_lines(sh):
        try:
            recs.append(json.loads(line))
        except ValueError:
            pass
    if recs:
        r += "<p><span class='pill pass'>passive</span> Shodan InternetDB — no traffic to the target</p>"
        rows = []
        for d in sorted(recs, key=lambda x: x.get("ip", "")):
            ports = " ".join(f"<span class='tag p'>{esc(p)}</span>" for p in d.get("ports", []))
            vulns = " ".join(f"<span class='tag v'>{esc(v)}</span>" for v in d.get("vulns", [])[:12])
            hosts = ", ".join(esc(h) for h in d.get("hostnames", [])[:3]) or "—"
            rows.append((f"<code>{esc(d.get('ip',''))}</code>", ports, hosts, vulns or "—"))
        r.table(["IP", "ports", "hostnames", "known CVEs"], rows)

    # Firewalled IPs answer on an improbable number of ports (SYN-ACK / tcpwrapped on
    # everything): a filtering device, not real services. Keep them out of the table.
    fw = {}
    for l in read_lines(os.path.join(w, "recon/ports/firewalled.txt")):
        p = l.split("\t")
        if p and p[0]:
            fw[p[0]] = p[1] if len(p) > 1 else "?"

    svc = read_lines(services)
    if svc:
        r += "<p><span class='pill act'>active</span> naabu + nmap service detection</p>"
        rows = []
        for l in svc:
            parts = l.split(None, 1)
            ip = parts[0] if parts else l
            if ip in fw:
                continue
            rest = parts[1] if len(parts) > 1 else ""
            rows.append((f"<code>{esc(ip)}</code>", f"<code>{esc(rest)}</code>"))
        if rows:
            r.table(["IP", "port / state / service / version"], rows)
        else:
            r += "<p class=muted>No host with a plausible set of open ports.</p>"
    if fw:
        listed = ", ".join(f"{esc(ip)} (~{esc(n)} ports)" for ip, n in sorted(fw.items()))
        r += (f"<p class=muted><strong>{len(fw)} IP(s) left out as firewalled:</strong> "
              f"they answered on an improbable number of ports (SYN-ACK / tcpwrapped on "
              f"everything), which is a filtering device, not real services — {listed}.</p>")


def section_secrets(w, r, nav):
    jsonl = os.path.join(w, "recon/secrets/th_all.jsonl")
    findings = []
    for line in read_lines(jsonl):
        try:
            findings.append(json.loads(line))
        except ValueError:
            pass
    code_leads = []
    for cs in glob.glob(os.path.join(w, "recon/secrets/*/code_search.txt")):
        code_leads += read_lines(cs)
    if not findings and not code_leads:
        return
    nav.append(("secrets", "Secrets"))
    r += "<h2 id=secrets>Secrets</h2>"
    r += "<p class=muted>Secrets are masked. The in-scope flag is a heuristic — the scope decision stays manual.</p>"
    if findings:
        rows = []
        for d in findings:
            det = d.get("DetectorName", "?")
            src = d.get("SourceMetadata", {}).get("Data", {}).get("Git", {})
            repo = src.get("repository", "")
            commit = (src.get("commit", "") or "")[:10]
            fpath = src.get("file", "")
            verified = "✓" if d.get("Verified") else "?"
            rows.append((esc(det), verified, f"<code>{esc(repo)}</code>", f"<code>{esc(commit)}</code>", f"<code>{esc(fpath)}</code>"))
        r.table(["provider", "verified", "repo", "commit", "file"], rows)
    else:
        r += "<p class=empty>No verified secrets.</p>"
    if code_leads:
        r += f"<details><summary>code-search leads to review by hand — {len(code_leads)}</summary>"
        r += "<table>" + "".join(f"<tr><td class=u><code>{esc(l)}</code></td></tr>" for l in code_leads[:200]) + "</table></details>"


def section_triage(w, r, nav):
    t = os.path.join(w, "recon/triage")
    if not os.path.isdir(t):
        return

    def rows_tab(name, cols):
        out = []
        for l in read_lines(os.path.join(t, name)):
            parts = l.split("\t")
            parts += [""] * (cols - len(parts))
            out.append(tuple(f"<code>{esc(p)}</code>" for p in parts[:cols]))
        return out

    def rows_list(name):
        return [(f"<code>{esc(l)}</code>",) for l in read_lines(os.path.join(t, name))]

    # the lead buckets, each: (file, column headers OR None for a plain list, builder)
    leads = [
        ("api_open.txt", ["status", "size", "open JSON endpoint"], lambda: rows_tab("api_open.txt", 3)),
        ("fuzz_juicy.txt", ["host", "sensitive path answering 200"], lambda: rows_tab("fuzz_juicy.txt", 2)),
        ("js_secrets.txt", ["bundle", "secret-looking match"], lambda: rows_tab("js_secrets.txt", 2)),
        ("admin_panels.txt", None, lambda: rows_list("admin_panels.txt")),
        ("exposed_services.txt", None, lambda: rows_list("exposed_services.txt")),
        ("code_hosts.txt", None, lambda: rows_list("code_hosts.txt")),
        ("shodan_ports.txt", ["IP", "open ports", "CVEs"], lambda: rows_tab("shodan_ports.txt", 3)),
        ("wayback_interesting.txt", None, lambda: rows_list("wayback_interesting.txt")),
    ]
    surface = [
        ("API behind 401/403", "api_gated.txt", 2, ["status", "url"]),
        ("API-looking paths (any status)", "api_paths.txt", 2, ["status", "url"]),
        ("Fuzz 200s (walls dropped)", "fuzz_real.txt", 3, ["host", "size", "url"]),
        # paths & params, kept together — all mined offline from JS / robots / URLs,
        # each carrying the host(s) it was seen on so you know where to test it
        ("Paths mined from JS", "js_endpoints.txt", 2, ["route", "host(s)"]),
        ("Paths from robots / sitemap (non-standard)", "robots_nonstd.txt", 1, ["path"]),
        ("Interesting crawl URLs", "js_urls.txt", 1, ["url"]),
        ("Parameter names for fuzzing", "params.txt", 2, ["param", "host(s)"]),
        ("Real UUIDs in JS", "js_uuids.txt", 2, ["uuid", "host(s)"]),
    ]

    has_leads = any(read_lines(os.path.join(t, f)) for f, _, _ in leads)
    has_surface = any(read_lines(os.path.join(t, f)) for _, f, _, _ in surface)
    if not has_leads and not has_surface:
        return

    nav.append(("triage", "Triage"))
    r += "<h2 id=triage>Triage</h2>"
    r += ("<p class=muted>Offline pass over the recon catch — no traffic. A path found here is a "
          "candidate, not a confirmed endpoint: verify with a minimal-touch request by hand.</p>")

    titles = {"api_open.txt": "Open JSON 200 endpoints", "fuzz_juicy.txt": "Sensitive paths answering 200",
              "js_secrets.txt": "Secret-looking strings in JS bundles", "admin_panels.txt": "Admin / login surfaces",
              "exposed_services.txt": "Exposed dashboards / brokers", "code_hosts.txt": "Git / CI hosts",
              "shodan_ports.txt": "IPs with open ports (passive Shodan)",
              "wayback_interesting.txt": "Archived URLs with a juicy extension (Wayback)"}
    if has_leads:
        r += "<h3 class=host>🎯 Leads — look first</h3>"
        for fname, headers, build in leads:
            rows = build()
            if not rows:
                continue
            r += f"<h4>{esc(titles.get(fname, fname))} — {len(rows)}</h4>"
            if headers:
                r.table(headers, rows)
            else:
                r += "<table>" + "".join(f"<tr><td class=u>{c[0]}</td></tr>" for c in rows[:200]) + "</table>"

    if has_surface:
        for title, fname, cols, headers in surface:
            rows = rows_tab(fname, cols) if cols > 1 else rows_list(fname)
            if not rows:
                continue
            r += f"<details><summary>{esc(title)} — {len(rows)}</summary>"
            if cols > 1:
                r.table(headers, rows)
            else:
                r += "<table>" + "".join(f"<tr><td class=u>{c[0]}</td></tr>" for c in rows[:300]) + "</table>"
            r += "</details>"


def section_wayback(w, r, nav):
    base = os.path.join(w, "recon/wayback")
    urls = read_lines(os.path.join(base, "urls.txt"))
    interesting = read_lines(os.path.join(base, "interesting.txt"))
    params = read_lines(os.path.join(base, "params.txt"))
    if not urls and not interesting and not params:
        return
    nav.append(("wayback", "Wayback"))
    r += "<h2 id=wayback>Wayback &amp; archives</h2>"
    r += ("<p><span class='pill pass'>osint</span> historical URLs from public archives — no "
          "traffic to the target. Candidates, not confirmed: verify by hand.</p>")
    if interesting:
        r += f"<h4>Juicy extensions — {len(interesting)}</h4>"
        r += "<table>" + "".join(f"<tr><td class=u>{esc(u)}</td></tr>" for u in interesting[:200]) + "</table>"
    if params:
        rows = []
        for l in params:
            parts = l.split("\t") + [""]
            rows.append((f"<code>{esc(parts[0])}</code>", f"<code>{esc(parts[1])}</code>"))
        r += f"<h4>Parameter names from archives — {len(params)}</h4>"
        r.table(["param", "host(s)"], rows)
    if urls:
        r += f"<details><summary>all in-scope archived URLs — {len(urls)}</summary>"
        r += "<table>" + "".join(f"<tr><td class=u>{esc(u)}</td></tr>" for u in urls[:1000]) + "</table>"
        r += "</details>"


def section_snapshots(w, r, nav):
    base = os.path.join(w, "recon/snapshots")
    index = os.path.join(base, "index.html")
    pngs = sorted(glob.glob(os.path.join(base, "**", "*.png"), recursive=True))
    if not os.path.isfile(index) or not pngs:
        return
    nav.append(("snapshots", "Snapshots"))
    r += "<h2 id=snapshots>Snapshots</h2>"
    r += ("<p><span class='pill pass'>visual</span> "
          f"{len(pngs)} screenshot(s) of the live pages — "
          "<a href='recon/snapshots/index.html'>open the full gallery</a>. "
          "Candidates, not proof: verify by hand.</p>")
    r += "<div style='display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:10px'>"
    for p in pngs[:12]:
        rel = os.path.relpath(p, w)
        r += ("<a href='recon/snapshots/index.html' "
              "style='display:block;border:1px solid #21262d;border-radius:8px;overflow:hidden'>"
              f"<img loading=lazy src='{esc(rel)}' "
              "style='width:100%;height:120px;object-fit:cover;object-position:top;display:block'></a>")
    r += "</div>"
    if len(pngs) > 12:
        r += f"<p class=dim>… {len(pngs) - 12} more in the gallery</p>"


def section_retest(w, r, nav):
    runs = sorted(glob.glob(os.path.join(w, "recon/retest/2*")), reverse=True)
    runs = [d for d in runs if os.path.isdir(d)]
    if not runs:
        return
    nav.append(("retest", "Retest"))
    r += "<h2 id=retest>Retest history</h2>"
    rows = []
    for d in runs:
        stamp = os.path.basename(d)
        new = n_lines(os.path.join(d, "new_subs.txt"))
        live = n_lines(os.path.join(d, "new_live.txt"))
        gone = n_lines(os.path.join(d, "gone_subs.txt"))
        rows.append((esc(stamp), str(new), str(live), str(gone)))
    r.table(["run", "new subs", "new live", "gone"], rows, cap=50)
    newest = runs[0]
    nl = read_lines(os.path.join(newest, "new_live.txt"))
    if nl:
        r += f"<details><summary>new live hosts in the latest run — {len(nl)}</summary>"
        r += "<table>" + "".join(f"<tr><td class=u><code>{esc(l)}</code></td></tr>" for l in nl[:200]) + "</table></details>"



def section_js(w, r, nav):
    urls = read_lines(os.path.join(w, "js/_urls.txt"))
    bundles = sorted(glob.glob(os.path.join(w, "js/**/*.js"), recursive=True))
    if not urls and not bundles:
        return
    nav.append(("js", "JS"))
    r += "<h2 id=js>JavaScript</h2>"
    r += f"<p class=muted>{len(urls)} .js URL(s) discovered · {len(bundles)} bundle(s) downloaded under js/. Triage (secrets, hidden endpoints) is offline, by hand.</p>"
    if urls:
        r += f"<details open><summary>discovered .js URLs — {len(urls)}</summary>"
        r += "<table>" + "".join(f"<tr><td class=u><code>{esc(u)}</code></td></tr>" for u in urls[:300]) + "</table>"
        if len(urls) > 300:
            r += f"<p class=muted>… +{len(urls)-300} more</p>"
        r += "</details>"
    if bundles:
        rel = [os.path.relpath(b, w) for b in bundles]
        r += f"<details><summary>downloaded bundles — {len(bundles)}</summary>"
        r += "<table>" + "".join(f"<tr><td class=u><code>{esc(b)}</code></td></tr>" for b in rel[:300]) + "</table></details>"


def load_conf(w):
    conf = {}
    path = os.path.join(w, "kestrel.conf")
    for line in read_lines(path):
        if line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        conf[k] = v.strip().strip("'\"")
    return conf


def main(w, out):
    conf = load_conf(w)
    prog = conf.get("PROGRAM", os.path.basename(w.rstrip("/")))
    r = R()
    r += "<!doctype html><html lang=en><head><meta charset=utf-8>"
    r += "<meta name=viewport content='width=device-width,initial-scale=1'>"
    r += f"<title>kestrel · {esc(prog)}</title><style>{CSS}</style></head><body><div class=wrap>"
    r += f"<h1>kestrel — {esc(prog)}</h1>"
    sub = conf.get("PLATFORM", "")
    url = conf.get("PROGRAM_URL", "")
    if url:
        sub += f" · <a href='{esc(url)}'>{esc(url)}</a>"
    r += f"<div class=subt>{sub}</div>"
    r += f"<div class=meta>generated {esc(time.strftime('%Y-%m-%d %H:%M'))} · {esc(w)}</div>"

    apex = n_lines(os.path.join(w, "recon/apex.txt"))
    hosts = n_lines(os.path.join(w, "recon/hosts.txt"))
    cidr = n_lines(os.path.join(w, "recon/cidr_inscope.txt"))
    r += f"<div class=meta>scope: {apex} wildcard · {hosts} host · {cidr} IP range · port scan {'allowed' if conf.get('PORTSCAN_ALLOWED')=='y' else 'not allowed'}</div>"
    runs = read_lines(os.path.join(w, "notes/runs.log"))
    if runs:
        r += f"<div class=meta>last full recon: {esc(runs[-1].split()[0])}</div>"

    nav_items = []
    body = R()
    section_recon(w, body, nav_items)
    section_triage(w, body, nav_items)
    section_fuzz(w, body, nav_items)
    section_ports(w, body, nav_items)
    section_js(w, body, nav_items)
    section_snapshots(w, body, nav_items)
    section_wayback(w, body, nav_items)
    section_secrets(w, body, nav_items)
    section_retest(w, body, nav_items)

    if nav_items:
        r += "<nav>" + "".join(f"<a href='#{i}'>{esc(t)}</a>" for i, t in nav_items) + "</nav>"
    else:
        r += "<p class=empty>Nothing to report yet — run kestrel recon first.</p>"
    r.h += body.h
    r += "</div></body></html>"

    with open(out, "w", encoding="utf-8") as fh:
        fh.write("".join(r.h))
    print(f"SECTIONS={len(nav_items)}")
    print("NAMES=" + ",".join(t for _, t in nav_items))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2]))
