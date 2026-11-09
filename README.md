# kestrel

```
   _                 _                  _
  | | __  ___   ___ | |_   _ __   ___  | |
  | |/ / / _ \ / __|| __| | '__| / _ \ | |
  |   < |  __/ \__ \| |_  | |   |  __/ | |
  |_|\_\ \___| |___/ \__| |_|    \___| |_|
  bug-bounty recon framework
```

One command for every phase, program-aware: you describe a program **once** at
onboarding, and every command reads scope, identity and rules from there. The output is
uniform and deliberately lean — one header, one line per step with the numbers, and the
next command to run. Per-host lists never hit the screen; they go to files and the report.

```
kestrel doctor --install     # is this machine ready? install what's missing
kestrel new acme             # onboarding: scope, identity, rules (asked once)
kestrel recon acme           # full recon pipeline
kestrel status acme          # what it found, leads first
kestrel ports acme           # passive Shodan + active scan on owned IPs only
kestrel triage acme          # offline triage of the catch into leads
kestrel report acme          # one HTML report from whatever data exists
```

## Install

A Debian-based system (Kali, Ubuntu, Debian) is the primary target; other systems work, but
system packages must be installed by hand. **Go >= 1.21** must be installed by you
(`sudo apt install golang-go` on Kali / Ubuntu 24.04+, or https://go.dev/dl/): kestrel never
installs Go itself.

```
git clone <repo> ~/kestrel && bash ~/kestrel/install.sh
kestrel doctor --install
```

`install.sh` only puts `kestrel` on your PATH (a symlink into `~/.local/bin`). Tools are
installed by `doctor --install`: the ProjectDiscovery tools, ffuf and gitleaks with
`go install` into `~/.local/bin` (forcing `GOTOOLCHAIN=auto`, so an older packaged Go fetches
the toolchain the tools need), trufflehog with its official script, and nmap / gh / jq / ...
with apt. On non-Debian systems it tells you what to install by hand.

## Commands

| command | what it does | traffic |
|---|---|---|
| `kestrel new [program]` | onboarding (asked once) | none |
| `kestrel info [program]` | settings and scope summary | none |
| `kestrel scope [program]` | view / edit the scope, rebuilds derived files | none |
| `kestrel ls` | all programs: platform, last run, leads | none |
| `kestrel doctor [--install]` | tools, Go, gh auth, Shodan reachability, engine selftest | none |
| `kestrel recon [program] [stage]` | recon pipeline (full by default, resumable) | yes |
| `kestrel status [program]` | what the run produced, leads first | none |
| `kestrel verify [program]` | scope QA: nothing out of scope touched | none |
| `kestrel ports [program]` | Shodan InternetDB (passive) + naabu/nmap on owned IPs only | passive / yes |
| `kestrel triage [program]` | offline triage of recon/ports/js into leads | none |
| `kestrel retest [program]` | only what is new since the last scan | yes |
| `kestrel secrets [program]` | GitHub leak hunting | OSINT |
| `kestrel report [program]` | one HTML report from the data on disk | none |

The program name can be omitted: kestrel uses the last one you worked on. Every command has
`kestrel <command> --help` for its own options.

## Onboarding

`kestrel new` asks, once: name, platform, program URL, User-Agent suffix, custom header(s),
hosts and wildcards in / out of scope, IPs and ranges in / out of scope, paths out of scope,
wordlist, rate limit, program rules, whether port scanning is allowed, and whether to run recon
now.

Scope blocks can be **pasted straight from the program page**: kestrel extracts hosts,
wildcards, URLs and IP ranges and ignores the rest (and shows what it ignored). Out-of-scope IP
ranges are subtracted from the in-scope ones up front, and IPv6 ranges too large to scan are
left out.

**Out-of-scope paths** are literal path prefixes a program forbids on *every* host (e.g.
`/arcgis/`, `/internal/api/`). Paste them as-is; kestrel keeps the crawl out of them
(katana `-crawl-out-scope`), drops them from robots/sitemap targets and JS results so they are
never requested or surfaced as leads, keeps them out of the fuzz wordlist, and `verify` flags
any that slipped through. Leave the question empty when the program excludes no paths.

Each program lives in `<workspace>/<program>/`. The workspace (default `~/hunts`) is asked once
on the first `kestrel new` and saved in `~/.config/kestrel/config`; `KESTREL_BASE=<dir>`
overrides it for one run.

```
kestrel.conf     settings            scope            the scope (kestrel scope to edit)
headers.txt      custom headers      notes/rules.md   program rules
recon/ content/ js/   results        notes/*.log      engine + tool logs
report.html      the report          env.sh           legacy compatibility
```

## Recon pipeline

`kestrel recon` runs stage by stage and resumes an interrupted run automatically (`--fresh`
to start over, `--from <stage>`, `--skip a,b`, or a single stage by name):

```
enum  live  triage  catchall  quickhits  harvest  fuzz  summary  api  js
```

On screen it is one line per stage with the counts; everything else goes to
`notes/recon.log` and the report. It stops cleanly if nothing is live, and ends with a scope
verify (nothing out of scope touched, in-scope covered).

## Ports: ownership gate, firewall guard, preview

An in-scope hostname can resolve to an IP owned by a **third party** (a SaaS the target uses, a
CDN). Web testing of the hostname is routed by Host header and is fine; port-scanning that IP
hits the third party's infrastructure, which is outside almost every program's authorization.

- **Passive first.** Shodan InternetDB on the in-scope IPs and the IPs that in-scope hosts
  resolve to. Free, no key, zero packets to the target. Always runs.
- **Ownership gate.** The active scan only touches IPs inside an in-scope range, or whose
  Shodan hostname / reverse DNS is a scope domain. Everything else is written to
  `recon/ports/thirdparty.txt` and skipped. `--include-third-party` overrides this only if you
  are authorised.
- **Preview and confirm.** Before scanning, the approved targets are listed and you confirm.
  `-y` skips the prompt, `--dry-run` previews only, `--passive` stays passive.
- **Firewall guard.** A host that answers on an improbable number of ports is a filtering
  device (SYN-ACK / tcpwrapped on everything), not real services. Those IPs are flagged in
  `recon/ports/firewalled.txt` and kept out of the report's service table.

Active scanning runs only if the program allows it (answered at onboarding) and requires root
for a SYN scan; without root, naabu/nmap fall back to a slower connect scan.

## Triage (offline)

`kestrel triage` is a pure offline pass over what recon, ports and JS already collected — zero
network. It sorts the catch into lead files under `recon/triage/`, leads first:

- open JSON 200 endpoints, sensitive paths answering 200, admin / login surfaces, exposed
  dashboards and brokers, git / CI hosts;
- then the surface: APIs behind 401/403, paths mined from JS bundles, paths from robots /
  sitemap, interesting crawl URLs, a parameter-name wordlist for fuzzing, real UUIDs.

Paths mined from JS, parameter names and UUIDs each carry the host(s) they were seen on, so a
param like `id` or `s` tells you where to try it. Two plain, host-less wordlists are also written
— `recon/triage/paths_fuzz.txt` and `params_fuzz.txt` — ready to replay across the program's
other hosts.

Secret detection matches only real credential formats (AWS, Google, Slack, GitHub, JWT,
private keys) and secret-ish keys assigned a quoted, high-entropy literal — library
identifiers and placeholders are not flagged. A path found in a bundle is a candidate, not a
confirmed endpoint: verify it by hand with a minimal-touch request.

## Report

`kestrel report` builds one HTML page from whatever data is on disk — it works with any subset
of recon / ports / triage / secrets / retest already run, on demand, no traffic. The triage
pass is refreshed automatically each time, and ffuf blanket-403 walls and firewalled IPs are
collapsed so the real leads stand out. `--open` opens it in the browser.

## Retest

`kestrel retest` re-enumerates subdomains, compares against a saved baseline, finds which new
subdomains are live, and runs the web pipeline on just those. The first run seeds the baseline
(a big "new" count then is enumeration variance, not real assets; the reliable signal is what
is new **and** live). Port scanning is intentionally not part of retest — run `kestrel ports`
separately, so the ownership gate and confirmation always apply.

## Output

Every command prints one header, one line per step with the numbers, and the next command.
Lists never go to the screen: they are in the files under the program folder and in the report.
Engine output is in `notes/<command>.log`, tool output in `notes/tools.log`.

## Status

Early development (v0.1). All commands run through the single `kestrel` dispatcher with one
shared output style; engine scripts live in `libexec/`, Python helpers in `lib/`.
