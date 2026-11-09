#!/usr/bin/env python3
"""Passive port intel from Shodan InternetDB (free, no key, zero packets to the target).

    shodan_idb.py <workdir> [max_ips]

Inputs (whatever exists):
  recon/ip_targets.txt   in-scope IP ranges (minus out-of-scope), expanded to single IPs
  recon/resolved.txt     resolving in-scope hostnames → their IPv4 addresses (DNS only)
  recon/hosts.txt        standalone in-scope hosts (same)
Never queries an IP inside recon/cidr_oos.txt.

Outputs under recon/ports/:
  shodan.jsonl   one InternetDB record per IP that Shodan knows
  shodan.txt     ip · ports · hostnames · tags · vulns (human view)
Prints a summary as KEY=VALUE lines on stdout; progress on stderr.
"""
import ipaddress
import json
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
        with open(path) as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except FileNotFoundError:
        return []


def main(work, max_ips):
    recon = os.path.join(work, "recon")
    out_dir = os.path.join(recon, "ports")
    os.makedirs(out_dir, exist_ok=True)
    oos = [ipaddress.ip_network(c, strict=False) for c in lines(os.path.join(recon, "cidr_oos.txt"))]

    ips = {}  # ip -> source label
    capped = 0
    for c in lines(os.path.join(recon, "ip_targets.txt")):
        net = ipaddress.ip_network(c, strict=False)
        if net.version != 4:
            continue
        for ip in net:
            if len(ips) >= max_ips:
                capped += 1
                continue
            ips.setdefault(str(ip), "range")

    hosts = set()
    for f in ("resolved.txt", "hosts.txt"):
        for l in lines(os.path.join(recon, f)):
            hosts.add(l.split()[0].split("/")[0])
    socket.setdefaulttimeout(5)
    for h in sorted(hosts):
        try:
            for info in socket.getaddrinfo(h, None, socket.AF_INET):
                ip = info[4][0]
                if len(ips) < max_ips:
                    ips.setdefault(ip, h)
                else:
                    capped += 1
        except OSError:
            pass

    queried = known = open_ports = vulns = skipped_oos = errors = 0
    records = []
    total = len(ips)
    for n, (ip, src) in enumerate(sorted(ips.items(), key=lambda x: ipaddress.ip_address(x[0])), 1):
        addr = ipaddress.ip_address(ip)
        if any(addr in o for o in oos if o.version == addr.version):
            skipped_oos += 1
            continue
        print(f"\r   shodan {n}/{total} · known {known}", end="", file=sys.stderr, flush=True)
        queried += 1
        try:
            req = urllib.request.Request(API + ip, headers={"User-Agent": "kestrel"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                rec = json.load(r)
        except urllib.error.HTTPError as e:
            if e.code != 404:  # 404 = Shodan has nothing on this IP
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
        print("\r" + " " * 40 + "\r", end="", file=sys.stderr)

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

    print(f"IPS={total}")
    print(f"QUERIED={queried}")
    print(f"KNOWN={known}")
    print(f"PORTS={open_ports}")
    print(f"VULNS={vulns}")
    print(f"SKIPPED_OOS={skipped_oos}")
    print(f"CAPPED={capped}")
    print(f"ERRORS={errors}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 4096))
