#!/usr/bin/env python3
"""kestrel scope engine.

One human-readable scope file per program (<program>/scope):

    [in]
    *.example.com
    api.partner.io
    203.0.113.0/24
    [out]
    staging
    old.example.com
    203.0.113.128/25

From it, `build` regenerates the files the engine scripts read (same names bb-init wrote):

    recon/scope.txt        in-scope hosts & wildcards (legacy view)
    recon/apex.txt         wildcard roots, '*.' stripped      → enum
    recon/hosts.txt        standalone in-scope hosts          → live
    recon/oos.txt          out-of-scope hosts / keywords      → filter
    recon/cidr_inscope.txt in-scope IPs / CIDR (v4, v6)
    recon/cidr_oos.txt     out-of-scope IPs / CIDR
    recon/oos_paths.txt    out-of-scope path prefixes, excluded on every host → filter/crawl
    recon/ip_targets.txt   in-scope ranges MINUS out-of-scope ranges → ports --ranges

An optional [out_paths] section lists literal path prefixes the program excludes on
every host (e.g. /arcgis/), kept verbatim and normalized to a leading '/'.

Usage:
    scope.py normalize in|out   < pasted text   → clean entries on stdout, skipped lines on stderr
    scope.py build <workdir>                    → writes recon/*, prints a summary as KEY=VALUE lines
"""
import ipaddress
import os
import re
import sys

HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
WORD_RE = re.compile(r"^-?[a-z0-9][a-z0-9._-]*$")
SPLIT_RE = re.compile(r"[\s,;|]+")
V6_MAX_PREFIX = 112  # larger v6 ranges are not scannable


def as_network(tok):
    try:
        return ipaddress.ip_network(tok, strict=False)
    except ValueError:
        return None


def clean_token(tok):
    """Strip scheme, credentials, path, port and decoration from a pasted token."""
    t = tok.strip().strip("\"'`()[]<>").lower()
    t = re.sub(r"^[a-z][a-z0-9+.-]*://", "", t)
    t = t.split("/", 1)[0] if not as_network(t) else t
    t = t.split("@")[-1]
    if t.count(":") == 1 and not as_network(t):  # host:port
        t = t.split(":", 1)[0]
    return t.rstrip(".")


def classify(tok):
    """→ ('ip', net) | ('wildcard', root) | ('host', name) | (None, None)"""
    t = clean_token(tok)
    if not t:
        return None, None
    net = as_network(t)
    if net is not None:
        return "ip", str(net) if "/" in t else t
    if t.startswith("*."):
        root = t[2:]
        if HOST_RE.match(root):
            return "wildcard", "*." + root
        return None, None
    if HOST_RE.match(t):
        return "host", t
    return None, None


def normalize(section, lines):
    """Extract scope entries from pasted text. Returns (entries, skipped_lines)."""
    out, skipped, seen = [], [], set()
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        found = []
        for tok in SPLIT_RE.split(line):
            kind, val = classify(tok)
            if kind:
                found.append(val)
        if not found and section == "out":
            # out-of-scope keyword (e.g. 'staging', '-dev.'), only when the line is a single word
            word = line.lower()
            if WORD_RE.match(word):
                found.append(word)
        if not found:
            skipped.append(line)
        for v in found:
            if v not in seen:
                seen.add(v)
                out.append(v)
    return out, skipped


def read_scope(path):
    sec = {"in": [], "out": [], "out_paths": []}
    cur = None
    with open(path) as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower() in ("[in]", "[out]", "[out_paths]"):
                cur = line.lower()[1:-1]
                continue
            if cur:
                sec[cur].append(line)
    return sec


def subtract(ins, oos):
    """in-scope networks minus out-of-scope ones. Returns (targets, skipped_v6)."""
    targets, skipped = [], []
    for n in ins:
        if n.version == 6 and n.prefixlen < V6_MAX_PREFIX:
            skipped.append(str(n))
            continue
        parts = [n]
        for e in oos:
            nxt = []
            for p in parts:
                if e.version != p.version or not p.overlaps(e):
                    nxt.append(p)
                elif p.subnet_of(e):
                    continue  # fully excluded
                else:
                    nxt.extend(p.address_exclude(e))
            parts = nxt
        targets.extend(parts)
    return sorted(set(targets), key=lambda x: (x.version, x)), skipped


def write(path, items):
    with open(path, "w") as fh:
        for i in items:
            fh.write(f"{i}\n")


def build(work):
    sec = read_scope(os.path.join(work, "scope"))
    recon = os.path.join(work, "recon")
    os.makedirs(recon, exist_ok=True)

    apex, hosts, cidr_in, cidr_oos, oos, legacy = [], [], [], [], [], []
    for e in sec["in"]:
        kind, val = classify(e)
        if kind == "wildcard":
            apex.append(val[2:]); legacy.append(val)
        elif kind == "host":
            hosts.append(val); legacy.append(val)
        elif kind == "ip":
            cidr_in.append(val)
    for e in sec["out"]:
        kind, val = classify(e)
        if kind == "ip":
            cidr_oos.append(val)
        elif kind == "wildcard":
            oos.append(val[2:])
        elif kind == "host":
            oos.append(val)
        elif WORD_RE.match(e.lower()):
            oos.append(e.lower())

    # out-of-scope PATHS: literal path prefixes excluded on EVERY host (e.g. /arcgis/).
    # Kept verbatim (paths can be case-sensitive); only normalized to a leading '/'.
    oos_paths = []
    for e in sec.get("out_paths", []):
        p = e.strip()
        if not p or p == "/":
            continue
        if not p.startswith("/"):
            p = "/" + p
        oos_paths.append(p)

    uniq = lambda xs: sorted(set(xs))
    write(os.path.join(recon, "scope.txt"), legacy)
    write(os.path.join(recon, "apex.txt"), uniq(apex))
    write(os.path.join(recon, "hosts.txt"), uniq(hosts))
    write(os.path.join(recon, "oos.txt"), uniq(oos))
    write(os.path.join(recon, "cidr_inscope.txt"), uniq(cidr_in))
    write(os.path.join(recon, "cidr_oos.txt"), uniq(cidr_oos))
    write(os.path.join(recon, "oos_paths.txt"), uniq(oos_paths))

    targets, skipped_v6 = subtract(
        [ipaddress.ip_network(c, strict=False) for c in uniq(cidr_in)],
        [ipaddress.ip_network(c, strict=False) for c in uniq(cidr_oos)],
    )
    write(os.path.join(recon, "ip_targets.txt"), [str(t) for t in targets])

    print(f"WILDCARDS={len(set(apex))}")
    print(f"HOSTS={len(set(hosts))}")
    print(f"OOS={len(set(oos))}")
    print(f"CIDR_IN={len(set(cidr_in))}")
    print(f"CIDR_OOS={len(set(cidr_oos))}")
    print(f"OOS_PATHS={len(set(oos_paths))}")
    print(f"TARGET_RANGES={len(targets)}")
    print(f"TARGET_IPS={sum(t.num_addresses for t in targets)}")
    print(f"SKIPPED_V6={' '.join(skipped_v6)}")


def main(argv):
    if len(argv) == 3 and argv[1] == "normalize" and argv[2] in ("in", "out"):
        entries, skipped = normalize(argv[2], sys.stdin.read().splitlines())
        for e in entries:
            print(e)
        for s in skipped:
            print(s, file=sys.stderr)
        return 0
    if len(argv) == 3 and argv[1] == "build":
        build(argv[2])
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
