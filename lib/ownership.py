#!/usr/bin/env python3
"""Decide which IPs an active port scan is allowed to touch.

    ownership.py <workdir>

An in-scope HOSTNAME may resolve to an IP that belongs to a THIRD PARTY (a SaaS the target
uses, a CDN, someone else's server). Web testing of the hostname is routed by Host header, but
PORT-SCANNING that IP hits the third party's infrastructure — outside almost every program's
authorization. This classifies the IPs the in-scope hosts resolve to:

  OWNED  — the IP is inside an in-scope declared range (recon/cidr_inscope.txt), OR its reverse
           DNS (PTR) ends in a scope domain. These are safe to scan.
  THIRD-PARTY — neither. Skipped by default; the active scan never touches them.

Writes under recon/ports/:
  owned_ips.txt     one IP per line, safe to scan (plus the declared in-scope ranges)
  thirdparty.txt    ip <TAB> hostname <TAB> ptr   — skipped, for the report
Prints a summary as KEY=VALUE lines.
"""
import ipaddress
import json
import os
import socket
import sys


def lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def scope_domains(w):
    doms = set()
    for d in lines(os.path.join(w, "recon/apex.txt")):
        doms.add(d.lower().lstrip("."))
    for h in lines(os.path.join(w, "recon/hosts.txt")):
        h = h.lower().strip(".")
        doms.add(h)
        parts = h.split(".")
        # parent domain, only when the host has >=3 labels (keeps example.gov.uk, drops bare TLDs)
        if len(parts) >= 3:
            doms.add(".".join(parts[1:]))
    return {d for d in doms if d.count(".") >= 1}


def host_from(line):
    # strip scheme, trailing "[...]" fields, path and port → bare hostname
    s = line.split()[0] if line.split() else line
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/")[0]
    if s.count(":") == 1:
        s = s.split(":")[0]
    return s.strip().lower().strip(".")


def input_hosts(w):
    hosts = []
    for f in ("recon/live.txt", "recon/surface_ok.txt", "recon/hosts.txt"):
        for l in lines(os.path.join(w, f)):
            h = host_from(l)
            if h and h not in hosts:
                hosts.append(h)
    return hosts


def shodan_hostnames(w):
    """ip -> list of hostnames, from the passive Shodan layer (already fetched, no network)."""
    out = {}
    for line in lines(os.path.join(w, "recon/ports/shodan.jsonl")):
        try:
            d = json.loads(line)
        except ValueError:
            continue
        ip = d.get("ip")
        if ip:
            out[ip] = [h.lower() for h in d.get("hostnames", [])]
    return out


def ptr(ip):
    try:
        return socket.gethostbyaddr(ip)[0].lower().rstrip(".")
    except OSError:
        return ""


def ends_in_scope(name, doms):
    name = name.lower().rstrip(".")
    return any(name == d or name.endswith("." + d) for d in doms)


def main(w):
    ranges = []
    for c in lines(os.path.join(w, "recon/cidr_inscope.txt")):
        try:
            ranges.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    doms = scope_domains(w)
    sh_hosts = shodan_hostnames(w)
    out_dir = os.path.join(w, "recon/ports")
    os.makedirs(out_dir, exist_ok=True)

    owned, third = {}, {}  # ip -> host (owned) ; ip -> (host, ptr) (third-party)
    socket.setdefaulttimeout(5)
    for host in input_hosts(w):
        try:
            addrs = {ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)}
        except OSError:
            continue
        for ip in addrs:
            if ip in owned or ip in third:
                continue
            addr = ipaddress.ip_address(ip)
            if any(addr in r for r in ranges if r.version == 4):
                owned[ip] = host
                continue
            # Shodan already told us this IP's hostnames (no extra network): if any is a scope
            # domain the IP is the target's; if they are all third-party domains, it is not.
            sh = sh_hosts.get(ip, [])
            if any(ends_in_scope(h, doms) for h in sh):
                owned[ip] = host
                continue
            p = ptr(ip)
            reason = p or (",".join(sh) if sh else "-")
            if p and ends_in_scope(p, doms):
                owned[ip] = host
            else:
                third[ip] = (host, reason)

    with open(os.path.join(out_dir, "owned_ips.txt"), "w") as fh:
        for ip in sorted(owned, key=ipaddress.ip_address):
            fh.write(ip + "\n")
    with open(os.path.join(out_dir, "thirdparty.txt"), "w") as fh:
        for ip, (host, p) in sorted(third.items(), key=lambda x: ipaddress.ip_address(x[0])):
            fh.write(f"{ip}\t{host}\t{p}\n")

    print(f"OWNED={len(owned)}")
    print(f"THIRDPARTY={len(third)}")
    print(f"RANGES={len(ranges)}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
