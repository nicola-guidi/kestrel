#!/usr/bin/env python3
"""Export a program's scope to the formats Burp Suite and Caido import.

    export.py <workdir> <program> <outdir> burp|caido|both

Reads the derived scope files (recon/apex.txt, hosts.txt, oos.txt, cidr_inscope.txt,
cidr_oos.txt) and writes, under <outdir>:
  burp-scope.json    {"target":{"scope":{"include":[...],"exclude":[...]}}}  (host = regex)
  caido-scope.json   {"name","allowlist":[...],"denylist":[...]}             (glob *example.com)
  caido-scope.txt    the allow/deny glob lists, plain, to paste into Caido's scope UI

Scope comes straight from kestrel, so it is already in bounds: wildcards include their
subdomains, standalone hosts are exact, out-of-scope hosts/keywords become exclusions. IP
ranges are emitted where a host pattern can express them (single IPs, /24, /16, /8); anything
else is listed in the summary so you can add it by hand. Prints KEY=VALUE counts on stdout.
"""
import ipaddress
import json
import os
import re
import sys


def lines(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def is_ip_or_cidr(s):
    try:
        ipaddress.ip_network(s, strict=False)
        return True
    except ValueError:
        return False


def host_regex_exact(h):
    return "^" + re.escape(h) + "$"


def host_regex_wild(apex):
    # the apex itself and any subdomain of it
    return "^(.*\\.)?" + re.escape(apex) + "$"


def cidr_host_regex(cidr):
    """A host regex that matches the IPs of a /8, /16 or /24; None for anything else."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None
    if net.version != 4:
        return None
    if net.prefixlen == 32:
        return host_regex_exact(str(net.network_address))
    octets = str(net.network_address).split(".")
    if net.prefixlen == 24:
        return "^" + "\\.".join(octets[:3]) + "\\.\\d{1,3}$"
    if net.prefixlen == 16:
        return "^" + "\\.".join(octets[:2]) + "\\.\\d{1,3}\\.\\d{1,3}$"
    if net.prefixlen == 8:
        return "^" + octets[0] + "\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"
    return None


def build(work):
    recon = os.path.join(work, "recon")
    R = lambda *p: os.path.join(recon, *p)
    apex = lines(R("apex.txt"))
    hosts = lines(R("hosts.txt"))
    oos = lines(R("oos.txt"))
    cidr_in = lines(R("cidr_inscope.txt"))
    cidr_oos = lines(R("cidr_oos.txt"))
    return apex, hosts, oos, cidr_in, cidr_oos


def burp(apex, hosts, oos, cidr_in, cidr_oos):
    def entry(host_regex):
        return {"enabled": "true", "protocol": "any", "host": host_regex}
    include, exclude, skipped = [], [], []
    for a in apex:
        include.append(entry(host_regex_wild(a)))
    for h in hosts:
        include.append(entry(host_regex_exact(h)))
    for c in cidr_in:
        rx = cidr_host_regex(c)
        if rx:
            include.append(entry(rx))
        else:
            skipped.append(c)
    for o in oos:
        if is_ip_or_cidr(o):
            rx = cidr_host_regex(o)
            if rx:
                exclude.append(entry(rx))
            else:
                skipped.append(o)
        elif "." in o:
            exclude.append(entry(host_regex_wild(o)))   # the host and its subdomains
        else:
            exclude.append(entry(re.escape(o)))          # a keyword: substring match
    for c in cidr_oos:
        rx = cidr_host_regex(c)
        if rx:
            exclude.append(entry(rx))
        else:
            skipped.append(c)
    doc = {"target": {"scope": {"include": include, "exclude": exclude}}}
    return doc, skipped


def caido(program, apex, hosts, oos, cidr_in, cidr_oos):
    allow, deny, skipped = [], [], []
    for a in apex:
        allow.append("*" + a)   # Caido: any subdomain of a
        allow.append(a)         # the apex itself
    for h in hosts:
        allow.append(h)
    for c in cidr_in:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.prefixlen == 32:
            allow.append(str(net.network_address))
        else:
            skipped.append(c)   # Caido globs don't express CIDR cleanly
    for o in oos:
        if is_ip_or_cidr(o):
            try:
                net = ipaddress.ip_network(o, strict=False)
                if net.prefixlen == 32:
                    deny.append(str(net.network_address))
                else:
                    skipped.append(o)
            except ValueError:
                pass
        elif "." in o:
            deny.append("*" + o)
            deny.append(o)
        else:
            deny.append("*" + o + "*")
    for c in cidr_oos:
        skipped.append(c)
    # dedup preserving order
    allow = list(dict.fromkeys(allow))
    deny = list(dict.fromkeys(deny))
    doc = {"name": program, "allowlist": allow, "denylist": deny}
    return doc, skipped


def main(argv):
    if len(argv) < 5:
        print(__doc__, file=sys.stderr)
        return 2
    work, program, outdir, which = argv[1], argv[2], argv[3], argv[4]
    os.makedirs(outdir, exist_ok=True)
    apex, hosts, oos, cidr_in, cidr_oos = build(work)
    if not (apex or hosts or cidr_in):
        print("no scope to export — run: kestrel new / kestrel scope", file=sys.stderr)
        return 3

    if which in ("burp", "both"):
        doc, _ = burp(apex, hosts, oos, cidr_in, cidr_oos)
        p = os.path.join(outdir, "burp-scope.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        print(f"BURP_INCLUDE={len(doc['target']['scope']['include'])}")
        print(f"BURP_EXCLUDE={len(doc['target']['scope']['exclude'])}")
        print(f"BURP_FILE={p}")
    if which in ("caido", "both"):
        doc, _ = caido(program, apex, hosts, oos, cidr_in, cidr_oos)
        p = os.path.join(outdir, "caido-scope.json")
        with open(p, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        t = os.path.join(outdir, "caido-scope.txt")
        with open(t, "w", encoding="utf-8") as fh:
            fh.write("# allowlist\n" + "\n".join(doc["allowlist"]) + "\n")
            fh.write("# denylist\n" + "\n".join(doc["denylist"]) + "\n")
        print(f"CAIDO_ALLOW={len(doc['allowlist'])}")
        print(f"CAIDO_DENY={len(doc['denylist'])}")
        print(f"CAIDO_FILE={p}")
        print(f"CAIDO_TXT={t}")
    # ranges no host pattern can express (prefix not /8, /16, /24 or /32) → add them by hand.
    # Caido additionally can't express any CIDR as a glob; that is noted by the command.
    manual = []
    for c in cidr_in + cidr_oos:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.prefixlen not in (8, 16, 24, 32):
            manual.append(c)
    if manual:
        print(f"SKIPPED={','.join(sorted(set(manual)))}")
    # how many in-scope CIDR ranges (prefix < 32) Caido can't express as globs
    caido_cidr = sum(1 for c in cidr_in
                     if is_ip_or_cidr(c) and ipaddress.ip_network(c, strict=False).prefixlen < 32)
    if which in ("caido", "both") and caido_cidr:
        print(f"CAIDO_CIDR_OMITTED={caido_cidr}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
