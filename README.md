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
kestrel ports acme           # active port scan on the declared in-scope IP ranges only
kestrel shodan acme          # passive Shodan InternetDB over the collected IPs (no traffic)
kestrel wayback acme         # historical URLs from public archives (OSINT, no traffic)
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
| `kestrel ports [program]` | active naabu/nmap on the declared in-scope IP ranges only | yes |
| `kestrel shodan [program]` | passive Shodan InternetDB over the collected IPs | passive |
| `kestrel wayback [program]` | historical URLs from public archives (Wayback CDX + gau) | OSINT |
| `kestrel triage [program]` | offline triage of recon/ports/shodan/wayback/js into leads | none |
| `kestrel retest [program]` | only what is new since the last scan | yes |
| `kestrel secrets [program]` | GitHub leak hunting | OSINT |
| `kestrel report [program]` | one HTML report from the data on disk | none |
| `kestrel db <sub>` | per-program store: recall any host, IP or path with all you found | none |
| `kestrel export [program]` | export the scope to Burp Suite / Caido | none |
| `kestrel replay [program]` | re-send the discovered surface through Burp/Caido | yes (proxy) |
| `kestrel snapshot [program]` | screenshot the live pages into a visual gallery | yes |
| `kestrel schedule [program]` | run retest automatically on a schedule (systemd/cron) | none |

The program name can be omitted: kestrel uses the last one you worked on. Every command has
`kestrel <command> --help` for its own options.

## Onboarding

`kestrel new` asks, once: name, platform, program URL, User-Agent suffix, custom header(s),
hosts and wildcards in / out of scope, IPs and ranges in / out of scope, paths out of scope,
wordlist, rate limit, program rules, whether port scanning is allowed, whether to route traffic
through an intercepting proxy (Burp/Caido) by default, and whether to run recon now.

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

| path | what it holds |
|---|---|
| `kestrel.conf` | settings |
| `scope` | the scope (edit with `kestrel scope`) |
| `headers.txt` | custom headers |
| `notes/rules.md` | program rules |
| `recon/` `content/` `js/` | results |
| `notes/*.log` | engine + tool logs |
| `report.html` | the report |
| `env.sh` | legacy compatibility |

## Recon pipeline

`kestrel recon` runs stage by stage and resumes an interrupted run automatically (`--fresh`
to start over, `--from <stage>`, `--skip a,b`, or a single stage by name):

```
enum  live  triage  catchall  quickhits  harvest  fuzz  summary  api  js
```

On screen it is one line per stage with the counts; everything else goes to
`notes/recon.log` and the report. It stops cleanly if nothing is live, and ends with a scope
verify (nothing out of scope touched, in-scope covered).

## Ports: declared ranges only, resume, firewall guard

`kestrel ports` runs an **active** scan (naabu + nmap `-sV`, real packets) and nothing else — the
passive layer moved to its own command (`kestrel shodan`). It is deliberately strict about what
it touches:

- **Declared IPs only.** The targets are exactly the in-scope IP ranges/IPs you entered at
  onboarding, minus the out-of-scope ones (`recon/ip_targets.txt`). It does **not** resolve
  in-scope hostnames to IPs and scan those: a host resolving to an IP (often a SaaS/CDN tagged
  "Website Testing") does not authorise port-scanning that IP. If the program declares no IP
  ranges, there is nothing to scan here.
- **Preview and confirm.** Before scanning, the declared targets are listed and you confirm.
  `-y` skips the prompt, `--dry-run` previews only.
- **Resume.** A long scan can be interrupted and re-run: the finished naabu phase is reused and
  per-IP nmap results already collected are skipped. `--fresh` starts over.
- **Curated range ports.** In range mode it scans a curated set of ports where an exposed
  service is itself a likely finding (unauth DB/cache, admin panels, remote access, k8s/Docker
  APIs, NFS/rsync, alt-HTTP), not a blind top-100.
- **Firewall guard.** A host that answers on an improbable number of ports is a filtering
  device (SYN-ACK / tcpwrapped on everything), not real services. Those IPs are flagged in
  `recon/ports/firewalled.txt` and kept out of the report's service table.

Active scanning runs only if the program allows it (answered at onboarding) and requires root
for a SYN scan; without root, naabu/nmap fall back to a slower connect scan.

## Shodan (passive)

`kestrel shodan` is a separate, passive step — Shodan's free InternetDB, **zero packets to the
target**. It runs over everything recon collected, in priority order so the free-API budget hits
live assets first: IPs the in-scope hosts resolve to, then live IPs with open ports from
`kestrel ports`, then a distributed sample across the declared ranges. **Third-party IPs are
excluded entirely** — an IP a host resolves to that the target does not own (not in a declared
range, reverse DNS not a scope domain) is never queried and never written, only counted.
Out-of-scope IPs are never touched. `--max <n>` raises the query cap (default 4096). Results land
in `recon/ports/shodan.*` and feed triage and the report.

## Wayback (OSINT)

`kestrel wayback` pulls URLs the target's hosts exposed in the **past** — paths and parameters the
live crawl can't see — from public archives, with **zero packets to the target**. It is modular:

- **Wayback Machine CDX** always runs (no dependency, built on Python's stdlib).
- **gau** is used only if it is installed, adding CommonCrawl, OTX and urlscan; if it is missing,
  kestrel says so and runs the CDX step alone.

Everything is filtered back to scope — in-scope hosts only, out-of-scope hosts/keywords and
out-of-scope path prefixes dropped, static-asset noise removed. Archived URLs are **candidates,
not confirmed endpoints**: verify each by hand with a minimal-touch request. Output lands in
`recon/wayback/` (`urls.txt`, `params.txt`, `interesting.txt`) and feeds triage (the paths and
params join the fuzz lists, juicy extensions become a lead) and the report.

## Triage (offline)

`kestrel triage` is a pure offline pass over what recon, ports, shodan, wayback and JS already
collected — zero network. It sorts the catch into lead files under `recon/triage/`, leads first:

- open JSON 200 endpoints, sensitive paths answering 200, admin / login surfaces, exposed
  dashboards and brokers, git / CI hosts, IPs with open ports from passive Shodan, archived URLs
  with a juicy extension;
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

## Database (per program, queryable)

`kestrel db` is a SQLite store of everything kestrel collected on a target — in the spirit of
Metasploit's db (hosts / services / vulns), but built from kestrel's richer data. It does **not**
replace the flat files: they stay the source of truth, and the db is a derived store you can rebuild
any time by reading them (`db sync` is idempotent). **One db file per program**, at
`<program_dir>/kestrel.db`, inspectable with the `sqlite3` CLI or any viewer — nothing hidden. Each
program's db holds only its own data; nothing crosses between programs.

The program defaults to the last one you worked on, and every subcommand takes an explicit
`[program]` as its last argument.

```
kestrel db sync [program]    # read the program's files on disk into its db (idempotent)
kestrel db stats [program]   # row counts per table
kestrel db host www.acme.com # full dossier for one host (see below)
kestrel db ip 203.0.113.10   # full dossier for one IP
kestrel db path /admin       # every host exposing a URL whose path matches /admin
kestrel db view hosts        # LIVE hosts, aligned table (add --dead for the rest, -n N to limit)
kestrel db view services acme -s elastic   # table view with filters
kestrel db query "SELECT ip, port, service FROM ports WHERE service LIKE '%elastic%'"
```

`view` prints an aligned, one-line-per-row table (long cells are truncated with `…` so rows don't
wrap). `view hosts` shows only **live** hosts by default — the dead ones are noise; add `--dead`
(`-a`) to include them, and `-n N` to cap the rows. `query` instead returns raw tab-separated values,
untouched, for piping or copy-paste.

**Entity view — recall one host or IP and see everything.** The point of the db is that you ask
for a host, URL or IP and it gathers across every table at once:

- `kestrel db host <name>` — the host's live status, the IPs it resolves to, the services/ports on
  those IPs, Shodan + CVEs, every endpoint ever seen for it (live probe · crawl · wayback archive),
  and the triage leads attributed to it.
- `kestrel db ip <addr>` — the host(s) that resolve to the IP (so you know an open port on
  `203.0.113.10:80` already belongs to a host you browsed, same target, not a stranger), its
  services/ports and Shodan CVEs.
- `kestrel db path <substr>` — the pivot: every host exposing a URL whose path matches, across all
  data sources.

The host↔IP link comes from the resolution map `kestrel shodan` writes (`recon/ports/host_ip_map.txt`),
so run `shodan` before `db sync` to populate it.

Tables: `programs`, `hosts` (status/info), `ips`, `host_ips` (the resolution link), `ports`
(source active/shodan, with service + version), `vulns` (CVEs), `endpoints` (source live/crawl/wayback,
with host), `leads` (the triage buckets, host attributed). Each `sync` stamps a `snapshot`, the
groundwork for time diffs. Run `db sync` at the end of a program's pipeline (or whenever), then recall
or query across all of them.

`db view <kind>` gives a flat table view (`hosts|services|ports|endpoints|vulns|leads`) with filters
`-S <host>`, `-p <port>`, `-s <service>`, `--status <code>`, `-k <lead-kind>`, `-m <substr>`, `--live`;
pass `--all` (the default for the entity views) to span every program instead of one.

## Burp Suite / Caido integration

kestrel maps the surface; Burp and Caido work it by hand. The bridge is that kestrel already holds
the two things you'd otherwise re-enter into those tools — the **scope** and a **list of URLs** — so it
hands them over, and keeps the proxy in bounds exactly like itself. Three pieces, one shared setting
(`PROXY_URL`, default `http://127.0.0.1:8080`, asked once at onboarding and editable in `kestrel.conf`):

**1. Proxy passthrough.** Route the requests kestrel makes at the target through an intercepting proxy,
so its history/sitemap fills with the discovered surface. It is deliberately scoped to target traffic
only (httpx, katana, ffuf and the target `curl`s): crt.sh, subfinder's sources and DNS stay direct, so
the proxy never fills with OSINT noise.

```
kestrel recon acme --proxy        # this run only, through the configured proxy
kestrel recon acme --no-proxy     # this run only, never (even if the program defaults to on)
```

At onboarding you choose whether a program proxies **by default**; the two flags are the per-run
override. Before a proxied run kestrel **preflights the proxy port** and stops with a clear message if
nothing is listening, rather than firing a whole run at a dead proxy.

**2. Replay — the "I forgot the flag" safety net.** Re-running recon just to populate the proxy would
re-enumerate and re-fuzz for nothing. Instead `kestrel replay` takes the surface kestrel **already
found on disk** (live hosts, wayback URLs, crawl output, URL leads) and requests just those once
through the proxy — no re-enumeration.

```
kestrel replay acme               # hydrate Burp/Caido from what's already on disk
```

**3. Scope export.** `kestrel export` writes the program's scope in the formats Burp and Caido import,
so you don't re-enter it and the proxy's own scope matches kestrel's.

```
kestrel export acme               # both; or --burp / --caido
```

Output lands in `recon/export/`: `burp-scope.json` (Burp Target > Scope — host fields are regexes,
wildcards include their subdomains, out-of-scope hosts/keywords become exclusions) and
`caido-scope.json` + `caido-scope.txt` (Caido allow/deny globs). IP ranges are expressed where a host
pattern can (single IPs and /8, /16, /24); anything else is listed so you can add it by hand, and Caido
globs can't express CIDR at all (Burp handles those). The import formats shift between tool versions, so
check the first import once.

## Snapshots (visual recon)

`kestrel snapshot` screenshots the pages that matter and builds a gallery you skim to see at a
glance what each one is — login, admin panel, default page, error, real app. It is an **extra, not a
pipeline stage**: run it whenever you want a bit more info. It feeds nothing else (not the report,
not triage, not the db) and nothing depends on it. It drives `httpx -screenshot` (headless browser),
so it reuses a tool you already have; the only extra is a local **Chromium** (`doctor` lists it as
optional, installs it with apt). It is active traffic (it loads the pages), so it honours the
program's **rate** and identity, and is **proxy-aware** (`--proxy` sends the screenshot requests
through Burp/Caido too).

By default it shoots **one screenshot per live host** (`recon/live.txt`) — the real web surface, one
page per host. Use `--leads` to shoot only the **triage-flagged hosts** instead (admin panels, open
APIs, exposed services, juicy fuzz hits), deduped to one shot per host so the gallery stays small —
the triage buckets are URL-level, so without the dedup a host with many flagged paths would flood
the gallery, and historical wayback URLs are left out on purpose. Run `kestrel triage` first so the
leads exist.

```
kestrel snapshot acme             # one shot per live host (the full web surface)
kestrel snapshot acme --leads     # only the triage-flagged hosts (one shot each)
kestrel snapshot acme --surface   # the wider surface (recon/surface_ok.txt) instead
```

Output lands in `recon/snapshots/`: the PNGs plus `index.html`, a filterable grid with status and
title per host — open it in a browser. Screenshots are candidates, not
proof — verify a page by hand before acting on it.

## Scheduling

`kestrel schedule` runs `kestrel retest <program>` automatically on a cadence, so new live subdomains
surface (and, if notifications are configured, ping you) without you remembering to look.

```
kestrel schedule acme daily --at 03:00    # or weekly / monthly
kestrel schedule --list                   # what is scheduled
kestrel schedule acme --remove            # stop
```

It prefers a **systemd user timer** with `Persistent=true` — a run missed because the machine was off
is caught up at the next boot — and falls back to **crontab** where systemd isn't available. Either
way it runs **on your machine**, so the machine must be powered on at that time: cron skips a missed
run, systemd catches it up, and for true 24/7 coverage you want an always-on host (a small VPS, a home
server, a Pi). A systemd user timer only fires while you're logged in unless you enable lingering
(`loginctl enable-linger <user>`), which `schedule` reminds you about.

## Retest

`kestrel retest` re-enumerates subdomains, compares against a saved baseline, finds which new
subdomains are live, and runs the web pipeline on just those. The first run seeds the baseline
(a big "new" count then is enumeration variance, not real assets; the reliable signal is what
is new **and** live). Port scanning is intentionally not part of retest — run `kestrel ports`
separately, so the declared-ranges-only targeting and the confirmation prompt always apply.

## Output

Every command prints one header, one line per step with the numbers, and the next command.
Lists never go to the screen: they are in the files under the program folder and in the report.
Engine output is in `notes/<command>.log`, tool output in `notes/tools.log`.

## Status

Early development (v0.1). All commands run through the single `kestrel` dispatcher with one
shared output style; engine scripts live in `libexec/`, Python helpers in `lib/`.
