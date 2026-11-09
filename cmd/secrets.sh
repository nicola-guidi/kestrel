# shellcheck shell=bash
# kestrel secrets [program] — GitHub leak hunting. Nothing to type: the GitHub org is derived
# from the scope domains and accepted ONLY if its GitHub profile (website / email) matches a
# scope domain. Unconfirmed lookalikes are listed, never scanned.
# Engine: libexec/bb-secrets.sh (discover → scan → report), output in notes/secrets.log.

# secrets_candidates → candidate org logins from recon/apex.txt + hosts.txt roots
secrets_candidates() {
  { cat recon/apex.txt recon/hosts.txt 2>/dev/null; } | awk -F. 'NF>=2{
      first=$(NF-1)
      if (NF>=3 && (first=="co"||first=="com"||first=="gv"||first=="gov"||first=="ac"||first=="or"||first=="org"||first=="net")) first=$(NF-2)
      print first; print first"-"$NF; print first"corp"; print first"hq"
      d=$0; gsub(/\./,"-",d); print d
    }' | tr 'A-Z' 'a-z' | awk '!seen[$0]++'
}

# secrets_domains → scope domains (apex + hosts' registrable part), for matching
secrets_domains() {
  {
    cat recon/apex.txt recon/hosts.txt 2>/dev/null
    # parent of each standalone host (app.example.gov.uk → example.gov.uk), never a bare public suffix
    awk -F. 'NF>=3{p=$2; for(i=3;i<=NF;i++) p=p"."$i;
      n=split(p,a,"."); sl=a[n-1]
      if (n>=3 || (sl!="co"&&sl!="com"&&sl!="gv"&&sl!="gov"&&sl!="ac"&&sl!="or"&&sl!="org"&&sl!="net")) print p}' recon/hosts.txt 2>/dev/null
  } | tr 'A-Z' 'a-z' | awk 'NF' | sort -u
}

cmd_secrets() {
  local prog="" a
  for a in "$@"; do
    case "$a" in
      -h|--help) sed -n '2,5p' "$KESTREL_ROOT/cmd/secrets.sh" | sed 's/^# \{0,1\}//' >&2; return 0 ;;
      -*) ui_die "unknown option '$a'" "kestrel secrets --help" ;;
      *) prog="$a" ;;
    esac
  done
  prog="$(resolve_program "$prog")"
  load_program "$prog"
  ui_header secrets "$prog"
  local t miss=()
  for t in gh git jq trufflehog; do tool_ok "$t" || miss+=("$t"); done
  [ ${#miss[@]} -eq 0 ] || ui_die "missing: ${miss[*]}" "kestrel doctor --install"
  gh auth status >/dev/null 2>&1 || ui_die "gh is not authenticated" "gh auth login"

  # ---------------------------------------------------------------- 1 · find the org
  ui_section "GitHub organisation"
  local domains c info blog email confirmed=() lookalikes=()
  domains="$(secrets_domains)"
  ui_running org "checking candidates…"
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    info="$(gh api "orgs/$c" --jq '[.blog // "", .email // "", .html_url] | @tsv' 2>/dev/null)" || continue
    blog="$(printf '%s' "$info" | cut -f1 | tr 'A-Z' 'a-z')"; email="$(printf '%s' "$info" | cut -f2 | tr 'A-Z' 'a-z')"
    if printf '%s\n%s\n' "$blog" "$email" | grep -qFf <(printf '%s\n' "$domains"); then confirmed+=("$c")
    else lookalikes+=("$c"); fi
  done < <(secrets_candidates)

  if [ ${#confirmed[@]} -eq 0 ]; then
    ui_warn org "no GitHub organisation linked to the scope domains"
    [ ${#lookalikes[@]} -gt 0 ] && ui_info lookalike "${lookalikes[*]} — exist but not linked to the scope: not scanned"
    ui_blank; return 0
  fi
  ui_ok org "${confirmed[*]} (profile matches the scope)"
  [ ${#lookalikes[@]} -gt 0 ] && ui_info lookalike "${lookalikes[*]} — not linked to the scope: not scanned"

  # ---------------------------------------------------------------- 2 · discover → scan → report
  ui_section scan
  local org dir rc t0; t0=$(date +%s)
  local email_domains; email_domains="$(paste -sd, recon/apex.txt 2>/dev/null || true)"
  for org in "${confirmed[@]}"; do
    dir="recon/secrets/$org"; mkdir -p "$dir"; rc=0
    ui_running "$org" "discovering repos, scanning history…"
    {
      printf '\n===== secrets %s · %s =====\n' "$org" "$(date '+%F %T')"
      ORG="$org" SECDIR="$dir" EMAIL_DOMAINS="$email_domains" TOOLLOG="$WORK/notes/tools.log" \
        bash "$KESTREL_ROOT/libexec/bb-secrets.sh" all
    } >> notes/secrets.log 2>&1 || rc=$?
    local nr nf nl
    nr="$(count_lines "$dir/repo_urls.txt")"; nf="$(count_lines "$dir/th_all.jsonl")"; nl="$(count_lines "$dir/code_search.txt")"
    if [ "$nf" -gt 0 ]; then ui_warn "$org" "$nf VERIFIED secret(s) in $nr repos · $dir/secrets-verified.md"
    elif [ "$rc" -ne 0 ]; then ui_warn "$org" "$nr repos · issues (notes/secrets.log)"
    else ui_ok "$org" "$nr repos scanned · no verified secrets"; fi
    [ "$nl" -gt 0 ] && ui_info code-search "$nl lead(s) to review by hand · $dir/code_search.txt"
  done
  # keep the combined findings where status looks for them
  cat recon/secrets/*/th_all.jsonl > recon/secrets/th_all.jsonl 2>/dev/null || true

  ui_blank
  ui_ok done "$(ui_elapsed $(( $(date +%s) - t0 ))) · secrets are masked in the reports"
  ui_next "kestrel status $prog"
  ui_blank
}
