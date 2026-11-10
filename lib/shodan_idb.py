#!/usr/bin/env python3
"""Passive port intel from Shodan InternetDB (free, no key, zero packets to the target).

    shodan_idb.py <workdir> [max_ips]

Runs over EVERYTHING the recon collected, in priority order (so the free-API budget is
spent on live assets, not empty address space):
  1. IPs that in-scope hostnames resolve to  (recon/resolved.txt, recon/hosts.txt)
  2. live IPs with open ports found by the active scan  (recon/ports/naabu.txt)
  3. a distributed sample across the declared in-scope ranges  (recon/ip_targets.txt)

THIRD-PARTY IPs are excluded entirely. An IP a host resolves to that is neither inside a
declared in-scope range nor whose reverse DNS is a scope domain belongs to a SaaS/CDN; it is
never queried and never written — only counted (THIRDPARTY_EXCLUDED). IPs inside
recon/cidr_oos.txt are likewise never touched (SKIPPED_OOS).

Outputs under recon/ports/:
  shodan.jsonl   one InternetDB record per queried IP that Shodan knows (owned IPs only)
  shodan.txt     ip · ports · hostnames · tags · vulns (human view)
Prints a summary as KEY=VALUE lines on stdout; progress on stderr.
"""
import ipaddress
import json
import math
import os
import socket
import sys
import time
import urllib.error
import urllib.request

API = "https://internetdb.shodan.io/"
DELAY = 0.25          # ~4 lookups/s: gentle with a free public API
TIMEOUT = 10


def lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return []


def scope_domains(recon):
    doms = set()
    for d in lines(os.path.join(recon, "apex.txt")):
        doms.add(d.lower().lstrip("."))
    for h in lines(os.path.join(recon, "hosts.txt")):
        h = h.lower().strip(".")
        doms.add(h)
        parts = h.split(".")
        if len(parts) >= 3:            # parent domain, keeps example.gov.uk, drops bare TLDs
            doms.add(".".join(parts[1:]))
    return {d for d in doms if d.count(".") >= 1}


def ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    except OSError:
        return ""


def ends_in_scope(name, doms):
    name = name.lower().rstrip(".")
    return any(name == d or name.endswith("." + d) for d in doms)


def host_names(recon):
    names = set()
    for f in ("resolved.txt", "hosts.txt"):
        for l in lines(os.path.join(recon, f)):
            names.add(l.split()[0].split("/")[0])
    return names


def main(work, max_ips):
    recon = os.path.join(work, "recon")
    out_dir = os.path.join(recon, "ports")
    os.makedirs(out_dir, exist_ok=True)

    ranges = []
    for c in lines(os.path.join(recon, "cidr_inscope.txt")):
        try:
            n = ipaddress.ip_network(c, strict=False)
            if n.version == 4:
                ranges.append(n)
        except ValueError:
            pass
    oos = []
    for c in lines(os.path.join(recon, "cidr_oos.txt")):
        try:
            oos.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    doms = scope_domains(recon)

    def in_ranges(addr):
        return any(addr in r for r in ranges)

    def is_oos(addr):
        return any(addr in o for o in oos if o.version == addr.version)

    selected = []          # ordered list of (ip, source) to query
    seen = set()
    third_party = 0        # excluded: resolves from a scope host but not owned
    skipped_oos = 0
    host_ip_pairs = []     # (host, ip) resolution map for owned IPs → recon/ports/host_ip_map.txt
    ptr_cache = {}

    def cached_ptr(ip):
        if ip not in ptr_cache:
            ptr_cache[ip] = ptr(ip)
        return ptr_cache[ip]

    def consider(ip, src):
        """Add an already-owned IP to the queue (dedup, OOS-filtered)."""
        nonlocal skipped_oos
        if ip in seen:
            return
        seen.add(ip)
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if addr.version != 4:
            return
        if is_oos(addr):
            skipped_oos += 1
            return
        selected.append((ip, src))

    # ---- tier 1: IPs the in-scope hostnames resolve to (classify, drop third-party)
    socket.setdefaulttimeout(5)
    for h in sorted(host_names(recon)):
        try:
            addrs = {ai[4][0] for ai in socket.getaddrinfo(h, None, socket.AF_INET)}
        except OSError:
            continue
        for ip in addrs:
            addr = ipaddress.ip_address(ip)
            if is_oos(addr):
                if ip not in seen:
                    seen.add(ip)
                    skipped_oos += 1
                continue
            owned = in_ranges(addr)
            if not owned:
                p = cached_ptr(ip)
                owned = bool(p and ends_in_scope(p, doms))
            if owned:
                host_ip_pairs.append((h, ip))   # record the resolution (every host→ip pair)
                consider(ip, h)                  # querying is deduped inside consider
            elif ip not in seen:
                seen.add(ip)                     # third-party: never queried, never written
                third_party += 1

    # ---- tier 2: live IPs with open ports from the active scan (inside declared ranges)
    for l in lines(os.path.join(recon, "ports/naabu.txt")):
        ip = l.split(":")[0].strip()
        consider(ip, "ports")

    # ---- tier 3: distributed sample across the declared ranges, to fill the remaining budget
    pool = []
    for r in ranges:
        for ip in r:
            s = str(ip)
            if s in seen:
                continue
            if is_oos(ip):
                skipped_oos += 1
                continue
            pool.append(s)
    capped = 0
    remaining = max_ips - len(selected)
    if pool:
        if remaining <= 0:
            capped += len(pool)
        else:
            step = max(1, math.ceil(len(pool) / remaining))
            picked = 0
            for i in range(0, len(pool), step):
                if len(selected) >= max_ips:
                    break
                consider(pool[i], "range")
                picked += 1
            capped += max(0, len(pool) - picked)
    # tiers 1+2 alone may already exceed the budget → trim and count the overflow
    if len(selected) > max_ips:
        capped += len(selected) - max_ips
        del selected[max_ips:]

    # ---- query InternetDB
    queried = known = open_ports = vulns = errors = 0
    records = []
    total = len(selected)
    for n, (ip, src) in enumerate(selected, 1):
        print(f"\r   shodan {n}/{total} · known {known}", end="", file=sys.stderr, flush=True)
        queried += 1
        try:
            req = urllib.request.Request(API + ip, headers={"User-Agent": "kestrel"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                rec = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code != 404:          # 404 = Shodan has nothing on this IP
                errors += 1
            rec = None
        except (urllib.error.URLError, OSError, ValueError):
            errors += 1
            rec = None
        if rec and rec.get("ports"):
            rec["source"] = src
            records.append(rec)
            known += 1
            open_ports += len(rec.get("ports", []))
            vulns += len(rec.get("vulns", []))
        time.sleep(DELAY)
    if total:
        print("\r" + " " * 48 + "\r", end="", file=sys.stderr)

    records.sort(key=lambda r: ipaddress.ip_address(r.get("ip", "0.0.0.0")))
    with open(os.path.join(out_dir, "shodan.jsonl"), "w") as fh:
        for r in records:
            fh.write(json.dumps(r) + "\n")
    with open(os.path.join(out_dir, "shodan.txt"), "w") as fh:
        for r in records:
            fh.write(
                f"{r['ip']:<16} ports={','.join(map(str, r.get('ports', [])))}"
                f"  hosts={','.join(r.get('hostnames', [])[:3]) or '-'}"
                f"  tags={','.join(r.get('tags', [])) or '-'}"
                f"  vulns={len(r.get('vulns', []))}  via={r['source']}\n"
            )

    # host→IP resolution map (owned IPs only) — lets the db link an IP back to its hostname(s)
    with open(os.path.join(out_dir, "host_ip_map.txt"), "w", encoding="utf-8") as fh:
        for h, ip in sorted(set(host_ip_pairs)):
            fh.write(f"{h}\t{ip}\n")

    print(f"IPS={total}")
    print(f"QUERIED={queried}")
    print(f"KNOWN={known}")
    print(f"PORTS={open_ports}")
    print(f"VULNS={vulns}")
    print(f"SKIPPED_OOS={skipped_oos}")
    print(f"THIRDPARTY_EXCLUDED={third_party}")
    print(f"CAPPED={capped}")
    print(f"ERRORS={errors}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 4096))
