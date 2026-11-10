#!/usr/bin/env python3
"""Historical URLs from public archives (OSINT — no traffic to the target).

    wayback.py <workdir> [extra_urls_file ...]

Queries the Wayback Machine CDX API for every in-scope apex/host and merges in any URLs passed
on extra files (e.g. the output of `gau`, if installed — collected by cmd/wayback.sh). Everything
is filtered back to scope: only in-scope hosts survive, out-of-scope hosts/keywords and
out-of-scope path prefixes are dropped, and static-asset noise is removed.

Archived URLs are CANDIDATES, not confirmed endpoints: verify by hand with a minimal-touch
request. Nothing here touches the target.

Writes under recon/wayback/:
  urls.txt         unique in-scope historical URLs (static assets dropped)
  params.txt       query-parameter name <TAB> host(s) it appeared on  (feeds param fuzzing)
  interesting.txt  URLs whose path ends in a juicy extension (.json/.bak/.sql/.env/.zip/...)
Prints a summary as KEY=VALUE lines on stdout; progress on stderr.
"""
import os
import re
import sys
import urllib.parse
import urllib.request

CDX = "http://web.archive.org/cdx/search/cdx"
TIMEOUT = 25

# static assets we never care about as endpoints
NOISE_EXT = re.compile(r"\.(?:png|jpe?g|gif|svg|ico|webp|bmp|css|woff2?|ttf|eot|otf|map|"
                       r"mp4|webm|avi|mov|mp3|wav|pdf)(?:$|\?)", re.I)
# extensions where the archived URL is itself worth a look
JUICY_EXT = re.compile(r"\.(?:json|xml|ya?ml|bak|old|orig|save|swp|sql|db|sqlite|dump|"
                       r"config|conf|ini|env|log|zip|tar|gz|tgz|rar|7z|war|jar|git|svn)(?:$|\?)", re.I)


def lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def host_of(url):
    try:
        h = urllib.parse.urlsplit(url).netloc
    except ValueError:
        return ""
    return h.split("@")[-1].split(":")[0].lower().strip(".")


def path_of(url):
    try:
        return urllib.parse.urlsplit(url).path or "/"
    except ValueError:
        return "/"


def fetch_cdx(q):
    url = f"{CDX}?{urllib.parse.urlencode(q)}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "kestrel"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.read().decode("utf-8", "replace").splitlines()
    except Exception:          # network/HTTP/parse — archives are best-effort
        return []


def main(work, extra_files):
    recon = os.path.join(work, "recon")
    out_dir = os.path.join(recon, "wayback")
    os.makedirs(out_dir, exist_ok=True)

    apexes = [a.lower().lstrip(".") for a in lines(os.path.join(recon, "apex.txt"))]
    hosts = [h.lower().strip(".") for h in lines(os.path.join(recon, "hosts.txt"))]
    oos_kw = [k.lower() for k in lines(os.path.join(recon, "oos.txt"))]
    oos_paths = [p if p.startswith("/") else "/" + p
                 for p in lines(os.path.join(recon, "oos_paths.txt"))]

    def in_scope_host(h):
        if not h:
            return False
        if any(k and k in h for k in oos_kw):
            return False
        if h in hosts:
            return True
        return any(h == a or h.endswith("." + a) for a in apexes)

    def path_oos(p):
        pl = p.lower()
        return any(pl.startswith(op.lower()) for op in oos_paths)

    # ---- collect raw URLs: Wayback CDX per apex (covers subdomains) + per standalone host
    raw = []
    q_base = {"output": "text", "fl": "original", "collapse": "urlkey"}
    for a in apexes:
        print(f"\r   wayback: cdx {a} …", end="", file=sys.stderr, flush=True)
        raw += fetch_cdx({**q_base, "url": a, "matchType": "domain"})
    for h in hosts:
        if any(h == a or h.endswith("." + a) for a in apexes):
            continue               # already covered by its apex domain query
        print(f"\r   wayback: cdx {h} …", end="", file=sys.stderr, flush=True)
        raw += fetch_cdx({**q_base, "url": h, "matchType": "host"})
    for f in extra_files:          # e.g. gau output, gathered by the shell wrapper
        raw += lines(f)
    if apexes or hosts:
        print("\r" + " " * 48 + "\r", end="", file=sys.stderr)

    # ---- filter back to scope, split into the three products
    urls, interesting = [], []
    params = {}                    # name -> set(hosts)
    seen = set()
    for u in raw:
        u = u.strip()
        if not u or "://" not in u:
            continue
        h = host_of(u)
        if not in_scope_host(h):
            continue
        p = path_of(u)
        if path_oos(p):
            continue
        # query params (attributed to the host, like triage) — before dropping static noise
        qs = urllib.parse.urlsplit(u).query
        for name, _ in urllib.parse.parse_qsl(qs, keep_blank_values=True):
            name = name.strip()
            if re.fullmatch(r"[A-Za-z_][\w\-]{0,39}", name or ""):
                params.setdefault(name, set()).add(h)
        if NOISE_EXT.search(u):
            continue
        if u not in seen:
            seen.add(u)
            urls.append(u)
            if JUICY_EXT.search(u):
                interesting.append(u)

    urls.sort()
    interesting.sort()
    param_rows = [f"{n}\t{','.join(sorted(hs))}" for n, hs in sorted(params.items())]

    def write(name, rows):
        with open(os.path.join(out_dir, name), "w", encoding="utf-8") as fh:
            fh.write("\n".join(rows) + ("\n" if rows else ""))
        return len(rows)

    n_urls = write("urls.txt", urls)
    n_interesting = write("interesting.txt", interesting)
    n_params = write("params.txt", param_rows)

    print(f"URLS={n_urls}")
    print(f"INTERESTING={n_interesting}")
    print(f"PARAMS={n_params}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2:]))
