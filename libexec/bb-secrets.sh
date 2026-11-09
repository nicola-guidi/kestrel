#!/usr/bin/env bash
#
# bb-secrets.sh — secret / credential leak hunting, phases 1-2 automated.
# Companion to bb-recon.sh. Implements the automatable part of
# metodologia/secret-hunting-playbook.md:
#
#   DISCOVER (GitHub, public OSINT via gh CLI):
#     - org repos (non-fork)
#     - public org members → their personal repos → their gists
#     - commits authored with a company email domain (cloak-preview search)
#     - code-search dorks → saved as leads for MANUAL review (not cloned)
#   SCAN:
#     - git clone --mirror of every candidate into an isolated dir
#     - trufflehog --only-verified over the FULL history (gitleaks optional complement)
#   REPORT:
#     - secrets-verified.md: provider, source (repo+commit+file), verified state, and an
#       in-scope HEURISTIC flag cross-referenced with scope.txt. Secrets are MASKED.
#
# NOT automated (left MANUAL by design, per the playbook):
#     - breach / combolist / credential stuffing (phase 4): sensitive + scope risk
#     - the fine validity check of "custom" keys, and the scope-gating / report decision (phase 5)
#
# This script is READ-ONLY. Discovery is public OSINT. Scanning reads local clones. trufflehog
# --only-verified makes ONE read-only validity call per candidate to its provider (that's the
# playbook's accepted check) and NEVER exploits a key beyond proving it is live. It opens no
# report and decides no scope — that stays with you.
#
# BEFORE running it, in EVERY session:
#     source ~/hunts/<prog>/env.sh
# then (ORG is required for discover/all):
#     ~/hunts/bb-secrets.sh check
#     ORG=acme ~/hunts/bb-secrets.sh all
#     ORG=acme EMAIL_DOMAINS='acme.com,acme.io' ~/hunts/bb-secrets.sh all
#     ~/hunts/bb-secrets.sh scan      # rescan existing clones
#     ~/hunts/bb-secrets.sh report    # rebuild the report from existing scan output
#
# Stages: all, check, discover, scan, report.
# Output under $WORK/recon/secrets/. Idempotent: safe to re-run.
set -euo pipefail
export LC_ALL=C

SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"

# ---------------------------------------------------------------- output helpers
log()  { printf '\033[1;36m[bb-secrets %s]\033[0m %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
ok()   { printf '   \033[1;32m✓\033[0m %s\n' "$*" >&2; }
warn() { printf '   \033[1;33m⚠\033[0m  %s\n' "$*" >&2; }
sub()  { printf '     \033[2m%s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[bb-secrets] ✗ %s\033[0m\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
need() { have "$1" || die "missing '$1' in PATH. Install it or skip this stage."; }

# ---------------------------------------------------------------- env guards
case "${1:-}" in check|-h|--help|help|"") SKIP_ENV=1 ;; esac
if [ -z "${SKIP_ENV:-}" ]; then
  [ -n "${WORK:-}" ]  || die "\$WORK not set. First run:  source ~/hunts/<prog>/env.sh"
  [ -d "$WORK" ]      || die "\$WORK ($WORK) is not a directory. Did you run bb-init.sh?"
  cd "$WORK"
  mkdir -p recon notes recon/secrets
fi

# ---------------------------------------------------------------- config
: "${ORG:=}"                                   # GitHub org/user to enumerate (required for discover/all)
: "${SCOPE_FILE:=${WORK:-}/recon/scope.txt}"   # for the in-scope heuristic
: "${APEX_FILE:=${WORK:-}/recon/apex.txt}"     # default email-domain source
# company email domains for the commit-author search (comma-separated). Default = the apex domains.
if [ -z "${EMAIL_DOMAINS:-}" ] && [ -s "${APEX_FILE:-/dev/null}" ]; then
  EMAIL_DOMAINS="$(paste -sd, "$APEX_FILE" 2>/dev/null || true)"
fi
: "${EMAIL_DOMAINS:=}"
: "${MAX_REPOS:=300}"        # cap org/user repo listings (avoid cloning thousands)
: "${MEMBERS_MAX:=50}"       # cap how many public members we follow into personal repos/gists
: "${INCLUDE_MEMBERS:=1}"    # 1 = also scan members' personal repos + gists (often where leaks are)
: "${INCLUDE_COMMIT_SEARCH:=1}"  # 1 = search commits by company email domain
: "${GITLEAKS:=0}"           # 1 = also run gitleaks as a complement to trufflehog
: "${TOOLLOG:=${WORK:-}/notes/tools.log}"

: "${SECDIR:=recon/secrets}"
export GIT_TERMINAL_PROMPT=0   # never hang on a credential prompt for a private/removed repo

# ---------------------------------------------------------------- check (tool preflight)
stage_check() {
  log "Checking tools (✓ present · ✗ missing):"
  local t name role lvl m miss=0
  for t in \
    "gh|GitHub discovery (must be authenticated: gh auth login)|core" \
    "git|clone the candidate repos|core" \
    "jq|parse gh + trufflehog JSON|core" \
    "trufflehog|secret scan of git history (--only-verified)|core" \
    "gitleaks|optional complement to trufflehog|opt" \
    "git-dumper|pull an exposed .git/ before scanning (manual)|opt" ; do
    name=${t%%|*}; role=${t#*|}; role=${role%|*}; lvl=${t##*|}
    if have "$name"; then m="✓"; else m="✗"; [ "$lvl" = core ] && miss=$((miss+1)); fi
    printf '   %s  %-11s %-50s [%s]\n' "$m" "$name" "$role" "$lvl" >&2
  done
  echo >&2
  if have gh; then
    if gh auth status >/dev/null 2>&1; then ok "gh is authenticated."
    else warn "gh present but NOT authenticated → run 'gh auth login' (discovery needs it)."; fi
  fi
  if [ "$miss" -eq 0 ]; then ok "CORE complete (gh, git, jq, trufflehog): discover + scan + report run."
  else warn "$miss CORE tool(s) missing: install them before proceeding."; fi
  sub "trufflehog: see github.com/trufflesecurity/trufflehog · gitleaks: github.com/gitleaks/gitleaks"
}

# ---------------------------------------------------------------- 1) discover (GitHub OSINT)
# Writes candidate repo URLs + a provenance map (type<TAB>url) used later for the in-scope flag.
stage_discover() {
  need gh; need jq
  [ -n "$ORG" ] || die "ORG not set. Run:  ORG=<github-org> ~/hunts/bb-secrets.sh discover"
  gh auth status >/dev/null 2>&1 || die "gh not authenticated. Run 'gh auth login' first."

  local SRC="$SECDIR/repo_src.txt"      # provenance: type<TAB>clone_url
  : > "$SRC"
  : > "$SECDIR/members.txt"
  : > "$SECDIR/code_search.txt"

  # 1a. org repos (skip forks: a fork's leak is usually upstream's, not the org's)
  log "org repos for '$ORG' (non-fork, cap $MAX_REPOS)"
  gh repo list "$ORG" --limit "$MAX_REPOS" --no-archived --source \
      --json url,isFork 2>>"$TOOLLOG" \
    | jq -r '.[] | select(.isFork|not) | "org\t"+.url+".git"' >> "$SRC" || \
      warn "org repo list failed (org name? gh scope?) — see $TOOLLOG"
  ok "org repos: $(grep -c '^org'$'\t' "$SRC" 2>/dev/null || true)"

  # 1b. public members → their personal repos → their gists
  if [ "$INCLUDE_MEMBERS" = 1 ]; then
    gh api "orgs/$ORG/members" --paginate 2>>"$TOOLLOG" | jq -r '.[].login' 2>/dev/null \
      | head -n "$MEMBERS_MAX" > "$SECDIR/members.txt" || true
    local nm; nm=$(wc -l < "$SECDIR/members.txt")
    if [ "$nm" -gt 0 ]; then
      log "public members: $nm (cap $MEMBERS_MAX) → their repos + gists"
      local u i=0
      while read -r u; do
        [ -z "$u" ] && continue
        i=$((i+1)); printf '\r   [%d/%d] %-40.40s' "$i" "$nm" "$u" >&2
        gh repo list "$u" --limit 100 --no-archived --source --json url,isFork 2>>"$TOOLLOG" \
          | jq -r '.[] | select(.isFork|not) | "member\t"+.url+".git"' >> "$SRC" || true
        gh api "users/$u/gists" --paginate 2>>"$TOOLLOG" \
          | jq -r '.[].git_pull_url | "gist\t"+.' >> "$SRC" 2>/dev/null || true
      done < "$SECDIR/members.txt"
      printf '\r%-60s\r' '' >&2
    else
      warn "no public members listed (private membership, or none) — skipping member repos/gists."
    fi
  else
    sub "INCLUDE_MEMBERS=0 → skipping members' repos and gists."
  fi

  # 1c. commits authored with a company email domain (often land in THIRD-PARTY repos → flagged later)
  if [ "$INCLUDE_COMMIT_SEARCH" = 1 ] && [ -n "$EMAIL_DOMAINS" ]; then
    log "commit search by email domain: $EMAIL_DOMAINS"
    local d
    while IFS=, read -r -d, d || [ -n "$d" ]; do
      d="$(printf '%s' "$d" | tr -d '[:space:]')"; [ -z "$d" ] && continue
      gh api -X GET search/commits -f q="author-email:@$d" --paginate \
          -H "Accept: application/vnd.github.cloak-preview+json" 2>>"$TOOLLOG" \
        | jq -r '.items[]?.repository.clone_url | select(.) | "commit\t"+.' >> "$SRC" 2>/dev/null || true
    done <<< "$EMAIL_DOMAINS,"
    ok "commit-linked repos: $(grep -c '^commit'$'\t' "$SRC" 2>/dev/null || true)"
  else
    sub "commit search skipped (INCLUDE_COMMIT_SEARCH=0 or no EMAIL_DOMAINS)."
  fi

  # 1d. code-search dorks → LEADS for manual review (code search needs login, indexed code only).
  #     We do NOT clone from these; they point you at specific files to open by hand.
  if [ -n "$ORG" ]; then
    local q
    for q in "org:$ORG filename:.env" "org:$ORG AWS_SECRET_ACCESS_KEY" \
             "org:$ORG filename:config password" "org:$ORG private_key" \
             "org:$ORG authorization bearer"; do
      {
        echo "## $q"
        gh api -X GET search/code -f q="$q" --paginate 2>>"$TOOLLOG" \
          | jq -r '.items[]?.html_url | select(.)' 2>/dev/null
        echo
      } >> "$SECDIR/code_search.txt" || true
    done
    ok "code-search leads (manual) → $SECDIR/code_search.txt"
  fi

  # de-dup the provenance map keeping the FIRST (strongest) type per url: org > member > gist > commit
  if [ -s "$SRC" ]; then
    awk -F'\t' '
      BEGIN{ r["org"]=1; r["member"]=2; r["gist"]=3; r["commit"]=4 }
      { if (!($2 in best) || r[$1] < r[best[$2]]) best[$2]=$1 }
      END{ for (u in best) print best[u]"\t"u }' "$SRC" | sort -t"$(printf '\t')" -k2 > "$SRC.tmp"
    mv "$SRC.tmp" "$SRC"
  fi
  cut -f2 "$SRC" | sort -u > "$SECDIR/repo_urls.txt"
  ok "candidate repos (deduped): $(wc -l < "$SECDIR/repo_urls.txt") → $SECDIR/repo_urls.txt"
  [ -s "$SECDIR/repo_urls.txt" ] || warn "no candidate repos found — check ORG and gh auth/scopes."
}

# ---------------------------------------------------------------- 2) scan (clone + trufflehog)
stage_scan() {
  need git; need trufflehog; need jq
  [ -s "$SECDIR/repo_urls.txt" ] || die "no $SECDIR/repo_urls.txt: run 'discover' first."
  mkdir -p "$SECDIR/repos"
  : > "$SECDIR/th_all.jsonl"

  local n; n=$(wc -l < "$SECDIR/repo_urls.txt")
  log "clone --mirror + trufflehog --only-verified over $n repos (full history)"
  local url i=0 dir slug
  while read -r url; do
    [ -z "$url" ] && continue
    i=$((i+1)); printf '\r   [%d/%d] %-45.45s' "$i" "$n" "$url" >&2
    # deterministic, filesystem-safe dir name from the URL
    slug="$(printf '%s' "$url" | sed -E 's#^https?://##; s#[^A-Za-z0-9._-]#_#g')"
    dir="$SECDIR/repos/$slug"
    if [ ! -d "$dir" ]; then
      git clone --mirror --quiet "$url" "$dir" >>"$TOOLLOG" 2>&1 || { warn "clone failed: $url"; continue; }
    fi
    # trufflehog reads the bare repo; one JSON object per finding, appended.
    trufflehog git "file://$dir" --only-verified --json 2>>"$TOOLLOG" \
      | jq -c --arg url "$url" '. + {bb_repo:$url}' >> "$SECDIR/th_all.jsonl" 2>>"$TOOLLOG" || true
    if [ "$GITLEAKS" = 1 ] && have gitleaks; then
      gitleaks detect --source "$dir" --no-banner \
        --report-format json --report-path "$SECDIR/gl_${slug}.json" >>"$TOOLLOG" 2>&1 || true
    fi
  done < "$SECDIR/repo_urls.txt"
  printf '\r%-70s\r' '' >&2

  local nh; nh=$(wc -l < "$SECDIR/th_all.jsonl")
  ok "verified trufflehog findings: $nh → $SECDIR/th_all.jsonl"
  [ "$GITLEAKS" = 1 ] && sub "gitleaks reports (unverified, review by hand): $SECDIR/gl_*.json"
}

# ---------------------------------------------------------------- 3) report (secrets-verified.md)
# Masks every secret. The in-scope flag is a HEURISTIC: org-owned source + a scope domain seen in
# the repo/metadata = likely in scope; member/gist/commit source = REVIEW; nothing = REVIEW.
# The real scope gating and the report decision stay manual (playbook phase 5).
stage_report() {
  need jq
  local OUT="$SECDIR/secrets-verified.md"
  local JL="$SECDIR/th_all.jsonl"
  [ -f "$JL" ] || die "no $JL: run 'scan' first."

  # scope domains (strip '*.') → newline list; provenance map (type<TAB>url) from discover
  local scope_tmp prov_tmp; scope_tmp="$(mktemp)"; prov_tmp="$(mktemp)"
  if [ -s "$SCOPE_FILE" ]; then sed -E 's/^[*.]+//; s/[[:space:]]+//g' "$SCOPE_FILE" | awk 'NF' | sort -u > "$scope_tmp"; fi
  [ -f "$SECDIR/repo_src.txt" ] && cp "$SECDIR/repo_src.txt" "$prov_tmp" || : > "$prov_tmp"

  local prog="${PROGRAM:-$(basename "${WORK:-.}")}"
  local now; now=$(date '+%Y-%m-%d %H:%M')
  local total; total=$(wc -l < "$JL")

  {
    printf '# Secrets verified — %s\n\n' "$prog"
    printf '_%s · %d verified finding(s) · source: GitHub discovery + trufflehog --only-verified_\n\n' "$now" "$total"
    echo '> ⚠️ Secrets are MASKED. "in-scope?" is a HEURISTIC (org source / scope domain seen) — the real'
    echo '> scope gating and the decision to open a report stay MANUAL. A third-party source is usually OOS.'
    echo
    if [ "$total" -eq 0 ]; then
      echo '_No verified secrets. (Good — or widen discovery: members, email domains, exposed .git.)_'
    else
      echo '| provider | in-scope? | source | repo | commit | file |'
      echo '|---|---|---|---|---|---|'
      jq -r --rawfile scope "$scope_tmp" --rawfile prov "$prov_tmp" '
        ($scope | split("\n") | map(select(length>0))) as $sd
        | ($prov | split("\n") | map(select(length>0) | split("\t")) | map(select(length==2))
                 | map({(.[1]): .[0]}) | add // {}) as $pm
        | (.DetectorName // "unknown") as $prov_name
        | (.SourceMetadata.Data.Git // {}) as $g
        | ($g.repository // .bb_repo // "-") as $repo
        | (($g.commit // "-")[0:10]) as $commit
        | ($g.file // "-") as $file
        | (.bb_repo // $repo) as $srcrepo
        | ($pm[$srcrepo] // "?") as $stype
        | (($srcrepo + " " + (.Raw // "") + " " + (.RawV2 // "")) | ascii_downcase) as $hay
        | ($sd | any(. as $d | $hay | contains($d))) as $scopehit
        | (if   $scopehit          then "scope-dom"
            elif $stype == "org"    then "org-src"
            else "review" end) as $flag
        | "| \($prov_name) | \($flag) | \($stype) | \($repo) | \($commit) | \($file) |"
      ' "$JL"
      echo
      echo '## Detail (masked)'
      echo
      jq -r '
        def mask: if type=="string" and (length>10) then (.[0:3] + "…" + (length|tostring) + "ch…" + .[-3:]) else "***" end;
        (.DetectorName // "unknown") as $prov_name
        | (.SourceMetadata.Data.Git // {}) as $g
        | "### \($prov_name) — \($g.repository // .bb_repo // "-")",
          "- secret: `\((.Raw // .RawV2 // "") | mask)`",
          "- verified: \(.Verified)",
          "- commit: \($g.commit // "-")  ·  file: \($g.file // "-")  ·  line: \($g.line // "-")",
          "- author: \($g.email // "-")  ·  when: \($g.timestamp // "-")",
          "- source repo: \(.bb_repo // "-")",
          ""
      ' "$JL"
    fi
    echo '---'
    echo '_Flags: scope-dom = a scope domain appears in the repo/secret · org-src = org-owned repo ·_'
    echo '_review = decide by hand. Next (manual): prove each secret unlocks an IN-SCOPE asset with a_'
    echo '_minimal read-only PoC, then decide on a report. Breach/combolist/stuffing stays manual too._'
  } > "$OUT"
  rm -f "$scope_tmp" "$prov_tmp"
  ok "report → $WORK/$OUT"
  sub "flags are heuristics — confirm scope by hand before any report."
}

# ---------------------------------------------------------------- all
run_stage() {
  local s="$1"; shift || true
  printf '\n\033[1;35m━━━━━━━━━━━━━━  %s  ━━━━━━━━━━━━━━\033[0m\n' "$s" >&2
  # '( ... ) || rc=$?' and NOT '( ... ); rc=$?': under 'set -e' a failing subshell aborts the
  # parent before the next command, so the ';' form would kill the whole run on a stage whose
  # last command returns non-zero. The '||' exempts it from set -e.
  local rc=0
  ( "stage_$s" "$@" ) || rc=$?
  [ "$rc" -eq 0 ] || warn "stage '$s' aborted (rc=$rc) — moving on."
  return 0
}
stage_all() {
  : > "$TOOLLOG"
  log "SECRET HUNTING — org=${ORG:-<unset>}  email=${EMAIL_DOMAINS:-<none>}"
  run_stage check
  run_stage discover
  run_stage scan
  run_stage report
  log "done. Open: $WORK/$SECDIR/secrets-verified.md"
}

# ---------------------------------------------------------------- dispatcher
usage() { sed -n '2,40p' "$SELF" >&2; exit 1; }
[ "$#" -ge 1 ] || usage
stage="$1"; shift || true
case "$stage" in
  check)    stage_check "$@" ;;
  discover) stage_discover "$@" ;;
  scan)     stage_scan "$@" ;;
  report)   stage_report "$@" ;;
  all)      stage_all "$@" ;;
  -h|--help|help) usage ;;
  *) die "unknown stage: '$stage'. Available: all, check, discover, scan, report." ;;
esac
log "stage '$stage' done."
