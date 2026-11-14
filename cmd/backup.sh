# shellcheck shell=bash
# kestrel backup — archive a program's whole folder (scope, recon data, db, report, notes) into one
# timestamped .tar.gz. Offline: reads files on disk, sends no traffic, changes nothing in the program.
#
# The archive holds everything the program folder holds, including headers.txt (your identity /
# tokens) and any verified secrets found, so it is written readable by you only (chmod 600). Treat it
# like the folder itself. To restore:  tar -xzf <archive> -C <workspace>   (it will not ask first).
#
#   kestrel backup [program] [--out DIR] [--lite] [--all]
#     --out DIR   where to write the archive (default: <workspace>/_backups)
#     --lite      leave out the screenshots (recon/snapshots): usually the bulk of the size
#     --all       back up every program, one archive each

_backup_one() { # <program> <outdir> <lite>
  local p="$1" out="$2" lite="$3"
  local dir; dir="$(program_dir "$p")"
  [ -d "$dir" ] || { ui_err "$p" "program folder not found: $dir"; return 1; }

  # an --out inside the program folder would archive the archive itself
  local rd ro; rd="$(cd -P "$dir" && pwd)"; ro="$(cd -P "$out" && pwd)"
  case "$ro/" in "$rd"/*) ui_err "$p" "--out is inside the program folder; pick another directory"; return 1 ;; esac

  local stamp file; stamp="$(date +%Y%m%d-%H%M%S)"
  local tag=""; [ "$lite" = 1 ] && tag="-lite"
  file="$ro/$p-$stamp$tag.tar.gz"
  # never overwrite an existing backup (two runs in the same second would collide)
  local n=1; while [ -e "$file" ]; do n=$((n+1)); file="$ro/$p-$stamp$tag-$n.tar.gz"; done
  local ex=(); [ "$lite" = 1 ] && ex=(--exclude="$p/recon/snapshots")

  local t0; t0=$(date +%s)
  ( umask 077; tar -C "$KESTREL_BASE" -czf "$file" ${ex[@]+"${ex[@]}"} "$p" ) \
    || { rm -f "$file"; ui_err "$p" "tar failed"; return 1; }
  # a backup you can't read back is not a backup
  tar -tzf "$file" >/dev/null 2>&1 || { ui_err "$p" "archive failed verification: $file"; return 1; }
  chmod 600 "$file" 2>/dev/null || true

  local size; size="$(du -h "$file" | cut -f1)"
  ui_ok "$p" "$size · $(tar -tzf "$file" | wc -l | tr -d ' ') entries · $(ui_elapsed $(( $(date +%s) - t0 )))"
  ui_info file "$file"
}

cmd_backup() {
  local prog="" out="" lite=0 all=0
  while [ $# -gt 0 ]; do
    case "$1" in
      -h|--help) sed -n '2,12p' "$KESTREL_ROOT/cmd/backup.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      --out)   shift; out="${1:-}" ;;
      --out=*) out="${1#--out=}" ;;
      --lite)  lite=1 ;;
      --all)   all=1 ;;
      -*) ui_die "unknown option '$1'" "kestrel backup --help" ;;
      *)  prog="$1" ;;
    esac
    shift
  done
  have tar || ui_die "tar is required"
  [ -n "$out" ] || out="$KESTREL_BASE/_backups"
  mkdir -p "$out" || ui_die "cannot create $out"
  chmod 700 "$out" 2>/dev/null || true

  local progs=()
  if [ "$all" -eq 1 ]; then
    local p; while IFS= read -r p; do [ -n "$p" ] && progs+=("$p"); done < <(list_programs)
    [ ${#progs[@]} -gt 0 ] || ui_die "no programs in $KESTREL_BASE" "kestrel new <program>"
    ui_header backup "all programs"
  else
    progs=("$(resolve_program "$prog")")
    ui_header backup "${progs[0]}"
  fi

  local fails=0 p
  for p in "${progs[@]}"; do _backup_one "$p" "$out" "$lite" || fails=$((fails+1)); done

  ui_blank
  ui_warn secrets "the archive contains headers.txt and any secrets found — keep it private"
  ui_next "restore: tar -xzf <archive> -C $KESTREL_BASE"
  ui_blank
  [ "$fails" -eq 0 ]
}
