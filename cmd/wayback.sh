# shellcheck shell=bash
# kestrel wayback [program] — historical URLs from public archives (OSINT, no traffic).
#
#   Pulls URLs the target's hosts exposed in the past, which the live crawl can't see:
#     1. Wayback Machine CDX API  (always — no dependency, zero packets to the target)
#     2. gau  (only if installed)  — adds CommonCrawl, OTX and urlscan sources
#   Everything is filtered back to scope: in-scope hosts only, out-of-scope hosts/keywords and
#   out-of-scope path prefixes dropped, static-asset noise removed.
#
#   Archived URLs are CANDIDATES, not confirmed endpoints — verify by hand, minimal touch.
#   Results land in recon/wayback/ and feed triage and the report.

cmd_wayback() {
  local prog="" a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,12p' "$KESTREL_ROOT/cmd/wayback.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      -*) ui_die "unknown option '$a'" "kestrel wayback --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header wayback "$prog"
  have python3 || ui_die "python3 is required" "kestrel doctor --install"
  [ -s recon/apex.txt ] || [ -s recon/hosts.txt ] || ui_die "no scope hosts yet" "kestrel new $prog"

  local t0; t0=$(date +%s)
  ui_section "osint · public archives (no traffic to the target)"
  mkdir -p recon/wayback

  # ---- step 2 (optional): gau, only if installed — more sources (CommonCrawl / OTX / urlscan)
  local extra=""
  if have gau; then
    ui_running gau "collecting URLs via gau (CommonCrawl / OTX / urlscan)…"
    extra="recon/wayback/_gau.txt"; : > "$extra"
    { cat recon/apex.txt 2>/dev/null; cat recon/hosts.txt 2>/dev/null; } | sort -u \
      | gau --subs --threads 5 >> "$extra" 2>>notes/wayback.log || true
    ui_ok gau "$(count_lines "$extra") URL(s) from gau → merged"
  else
    ui_info gau "gau not installed — Wayback CDX only (install gau for CommonCrawl / OTX / urlscan)"
  fi

  # ---- step 1 (always): Wayback CDX + scope filtering (the python helper does both)
  ui_running wayback "querying Wayback CDX + filtering to scope…"
  local out; out="$(python3 "$KESTREL_ROOT/lib/wayback.py" "$WORK" ${extra:+"$extra"} 2>/dev/null)" \
    || ui_die "wayback failed"
  local W_URLS W_INTERESTING W_PARAMS
  eval "$(printf '%s\n' "$out" | sed 's/^\([A-Z0-9_]*\)=\(.*\)$/W_\1=\x27\2\x27/')"
  rm -f recon/wayback/_gau.txt

  if [ "${W_URLS:-0}" -gt 0 ]; then
    ui_ok urls       "${W_URLS} in-scope historical URL(s) · recon/wayback/urls.txt"
    _tri_line ok wayback-juicy "${W_INTERESTING:-0}" "URL(s) with a juicy extension" recon/wayback/interesting.txt
    _tri_line info wayback-params "${W_PARAMS:-0}" "param name(s) seen in archives"  recon/wayback/params.txt
  else
    ui_info urls "no in-scope historical URLs found"
  fi

  ui_blank
  ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · recon/wayback/"
  ui_next "kestrel triage $prog"
  ui_blank
}
