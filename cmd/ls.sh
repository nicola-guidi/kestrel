# shellcheck shell=bash
# kestrel ls — all programs at a glance.

cmd_ls() {
  ui_header ls
  local progs p w plat last leads n=0
  progs="$(list_programs)"
  if [ -z "$progs" ]; then
    ui_info programs "none yet in $KESTREL_BASE"
    ui_next "kestrel new <program>"; ui_blank; return 0
  fi
  printf '  %-18s %-11s %-12s %s\n' PROGRAM PLATFORM 'LAST RUN' LEADS >&2
  while IFS= read -r p; do
    w="$(program_dir "$p")"
    plat="$( (PLATFORM=''; [ -f "$w/kestrel.conf" ] && . "$w/kestrel.conf"; printf '%s' "${PLATFORM:-legacy}") 2>/dev/null)"
    last="-"
    if [ -f "$w/notes/runs.log" ]; then last="$(tail -n1 "$w/notes/runs.log" | cut -d' ' -f1 | cut -dT -f1)"
    elif [ -f "$w/recon/live.txt" ]; then last="$(date -r "$w/recon/live.txt" +%Y-%m-%d 2>/dev/null || echo '?')"; fi
    leads=0
    for f in api_json quickhits_auth quickhits_interesting rescued browser_todo robots_targets; do
      leads=$((leads + $(count_lines "$w/recon/$f.txt")))
    done
    printf '  %-18s %-11s %-12s %s\n' "$p" "$plat" "$last" "$leads" >&2
    n=$((n+1))
  done <<< "$progs"
  ui_blank
  ui_info total "$n program(s) in $KESTREL_BASE"
  ui_blank
}
