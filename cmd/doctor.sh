# shellcheck shell=bash
# kestrel doctor [--install] — is this machine ready? Sends NO traffic to any target.
#
# --install: installs what is missing, after showing the list and asking once.
#   1. Go >= 1.21 is a prerequisite you install by hand: kestrel never installs Go.
#      (Go >= 1.21 fetches the newer toolchain the tools need by itself: kestrel forces
#       GOTOOLCHAIN=auto, because Debian's packaged Go defaults to 'local'.)
#   2. Go tools (ProjectDiscovery + ffuf + gitleaks) → go install, straight into ~/.local/bin
#   3. system packages (nmap, jq, gh, …) → apt, ONLY on Debian-based systems;
#      anywhere else kestrel prints an alert to install them by hand.

GO_MIN_MINOR=21
KESTREL_BIN_DIR="${KESTREL_BIN_DIR:-$HOME/.local/bin}"

# name | group | level (core|opt) | how: go:<module> · apt:<pkg> · script:<id>
DOCTOR_TOOLS=(
  "bash|core|core|apt:bash"
  "curl|core|core|apt:curl"
  "jq|core|core|apt:jq"
  "python3|core|core|apt:python3"
  "git|core|core|apt:git"
  "httpx|recon|core|go:github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "subfinder|recon|core|go:github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "dnsx|recon|opt|go:github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
  "ffuf|recon|core|go:github.com/ffuf/ffuf/v2@latest"
  "katana|recon|opt|go:github.com/projectdiscovery/katana/cmd/katana@latest"
  "naabu|ports|core|go:github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
  "nmap|ports|core|apt:nmap"
  "gh|secrets|core|apt:gh"
  "trufflehog|secrets|core|script:trufflehog"
  "gitleaks|secrets|opt|go:github.com/zricethezav/gitleaks/v8@latest"
)
DOCTOR_GROUPS=(core recon ports secrets)

# shodan_probe → HTTP code of one InternetDB lookup of a neutral public IP (never a target)
shodan_probe() {
  curl -s -o /dev/null -w '%{http_code}' --max-time 8 -A kestrel https://internetdb.shodan.io/8.8.8.8 2>/dev/null || true
}

is_debian() { [ -f /etc/debian_version ] && have apt-get; }

# go_minor → minor version of the installed Go (e.g. 22), empty if no Go
go_minor() {
  have go || return 0
  go version 2>/dev/null | sed -n 's/.*go1\.\([0-9][0-9]*\).*/\1/p'
}

# tool_ok <name> → present AND the right tool (Kali's 'httpx' can be the python client)
tool_ok() {
  local t="$1"
  have "$t" || return 1
  case "$t" in
    httpx) httpx -version 2>&1 | grep -qi projectdiscovery || return 1 ;;
    bash)  [ "${BASH_VERSINFO[0]}" -ge 4 ] || return 1 ;;
  esac
  return 0
}

tool_note() {
  case "$1" in
    httpx) have httpx && ! tool_ok httpx && printf 'wrong httpx on PATH (python client?) ' ;;
    bash)  [ "${BASH_VERSINFO[0]}" -lt 4 ] && printf 'bash >= 4 required ' ;;
  esac
}

# manual install hint for a tool
tool_hint() {
  local how="${1#*|*|*|}" name="${1%%|*}"
  case "$how" in
    go:*)     printf 'go install %s' "${how#go:}" ;;
    apt:*)    is_debian && printf 'sudo apt install %s' "${how#apt:}" || printf 'install %s with your package manager' "$name" ;;
    script:trufflehog) printf 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b %s' "$KESTREL_BIN_DIR" ;;
  esac
}

cmd_doctor() {
  local install=0 a
  for a in "$@"; do
    case "$a" in
      -h|--help) printf 'usage: kestrel doctor [--install]\n\n  Checks tools, wordlist and engine integrity. --install installs what is missing.\n' >&2; return 0 ;;
      --install) install=1 ;;
      *) ui_die "unknown option '$a'" "kestrel doctor --help" ;;
    esac
  done

  ui_header doctor
  local missing=() blocked=() g t name group level line
  for g in "${DOCTOR_GROUPS[@]}"; do
    local present=() need=() opt=()
    for t in "${DOCTOR_TOOLS[@]}"; do
      IFS='|' read -r name group level _ <<< "$t"
      [ "$group" = "$g" ] || continue
      if tool_ok "$name"; then present+=("$name")
      else
        missing+=("$t")
        if [ "$level" = core ]; then need+=("$name"); else opt+=("$name"); fi
      fi
    done
    line="${present[*]}"
    [ ${#need[@]} -gt 0 ] && line+="${line:+ · }missing: ${need[*]}"
    [ ${#opt[@]} -gt 0 ]  && line+="${line:+ · }optional: ${opt[*]}"
    if [ ${#need[@]} -gt 0 ]; then ui_err "$g" "$line"; blocked+=("$g")
    elif [ ${#opt[@]} -gt 0 ]; then ui_warn "$g" "$line"
    else ui_ok "$g" "$line"; fi
  done

  # ---------------------------------------------------------------- extra checks
  local gm; gm="$(go_minor)"
  if [ -z "$gm" ]; then ui_warn go "not installed — needed only to install the Go tools"
  elif [ "$gm" -lt "$GO_MIN_MINOR" ]; then ui_warn go "1.$gm is too old (need ≥ 1.$GO_MIN_MINOR) — update it by hand: https://go.dev/dl/"
  else ui_ok go "1.$gm"; fi

  if tool_ok nmap; then
    if [ "$(id -u)" -eq 0 ] || sudo -n true 2>/dev/null; then ui_ok privileges "root available: SYN scan"
    else ui_info privileges "no root: nmap/naabu fall back to the slower connect scan"; fi
  fi

  if tool_ok gh; then
    if gh auth status >/dev/null 2>&1; then ui_ok github "gh authenticated"
    else ui_warn github "gh not authenticated — run: gh auth login"; fi
  fi

  # Shodan InternetDB (passive layer of ports): one lookup of a neutral public IP, never a target
  local idb_code; idb_code="$(shodan_probe)"
  case "$idb_code" in
    200|404) ui_ok shodan "InternetDB reachable" ;;
    429)     ui_warn shodan "InternetDB rate-limited right now — retry later" ;;
    *)       ui_warn shodan "InternetDB unreachable (${idb_code:-no answer}) — ports will skip the passive layer" ;;
  esac

  case ":$PATH:" in
    *":$KESTREL_BIN_DIR:"*) : ;;
    *) ui_warn PATH "$KESTREL_BIN_DIR is not in \$PATH — tools installed there won't be found" ;;
  esac

  if [ -d "$KESTREL_BASE" ] && [ -w "$KESTREL_BASE" ]; then
    ui_ok workspace "$KESTREL_BASE ($(list_programs | grep -c . || true) programs)"
  elif [ -d "$KESTREL_BASE" ]; then ui_err workspace "$KESTREL_BASE is not writable"
  else ui_info workspace "$KESTREL_BASE (created on first kestrel new)"; fi

  local wl="$KESTREL_ROOT/wordlists/curated.txt"
  if [ -s "$wl" ]; then ui_ok wordlist "curated.txt ($(count_lines "$wl") entries)"
  else ui_err wordlist "$wl missing"; fi

  if bash "$KESTREL_ROOT/libexec/bb-selftest.sh" "$KESTREL_ROOT/libexec/bb-recon.sh" >/dev/null 2>&1; then
    ui_ok integrity "engine selftest passed"
  else
    ui_err integrity "engine selftest failed" ; blocked+=(engine)
  fi

  # ---------------------------------------------------------------- verdict
  ui_section verdict
  local ready="new · ls · scope · status · verify"
  [[ " ${blocked[*]} " != *" core "* ]] && [[ " ${blocked[*]} " != *" recon "* ]] && ready+=" · recon · retest"
  [[ " ${blocked[*]} " != *" core "* ]] && [[ " ${blocked[*]} " != *" ports "* ]] && ready+=" · ports"
  [[ " ${blocked[*]} " != *" core "* ]] && [[ " ${blocked[*]} " != *" secrets "* ]] && ready+=" · secrets"
  ui_ok ready "$ready"
  [ ${#blocked[@]} -gt 0 ] && ui_err blocked "${blocked[*]}"

  if [ ${#missing[@]} -eq 0 ]; then ui_blank; return 0; fi

  if [ "$install" -eq 0 ]; then
    ui_section "to install"
    for t in "${missing[@]}"; do printf '    %-11s %s\n' "${t%%|*}" "$(tool_note "${t%%|*}")$(tool_hint "$t")" >&2; done
    ui_blank
    ui_next "kestrel doctor --install"
    ui_blank
    [ ${#blocked[@]} -eq 0 ]; return
  fi

  doctor_install "${missing[@]}"
}

# ---------------------------------------------------------------- --install
doctor_install() {
  local go_items=() apt_items=() script_items=() manual=() t name how
  for t in "$@"; do
    name="${t%%|*}"; how="${t##*|}"
    case "$how" in
      go:*)     go_items+=("$name|${how#go:}") ;;
      apt:*)    if is_debian; then apt_items+=("${how#apt:}"); else manual+=("$t"); fi ;;
      script:*) script_items+=("$name") ;;
    esac
  done
  # naabu needs libpcap headers to build
  for t in "${go_items[@]}"; do [ "${t%%|*}" = naabu ] && is_debian && apt_items+=(libpcap-dev); done

  # Go is a prerequisite: stop here if it's missing or too old
  local gm; gm="$(go_minor)"
  if [ ${#go_items[@]} -gt 0 ] && { [ -z "$gm" ] || [ "$gm" -lt "$GO_MIN_MINOR" ]; }; then
    ui_section install
    if [ -z "$gm" ]; then ui_err go "Go is not installed"
    else ui_err go "Go 1.$gm is too old (need ≥ 1.$GO_MIN_MINOR)"; fi
    ui_dim "Install Go by hand (https://go.dev/dl/ — or 'sudo apt install golang-go' on Kali/Ubuntu 24.04+),"
    ui_dim "then run kestrel doctor --install again."
    ui_blank; return 1
  fi

  ui_section "install plan"
  [ ${#apt_items[@]} -gt 0 ]    && ui_info apt "sudo apt-get install -y ${apt_items[*]}"
  for t in "${go_items[@]}"; do ui_info go "${t%%|*}  → $KESTREL_BIN_DIR"; done
  for t in "${script_items[@]}"; do ui_info script "$t  → $KESTREL_BIN_DIR (official install script)"; done
  for t in "${manual[@]}"; do ui_warn manual "${t%%|*} not installed: install it by hand"; done
  if [ ${#apt_items[@]} -eq 0 ] && [ ${#go_items[@]} -eq 0 ] && [ ${#script_items[@]} -eq 0 ]; then
    ui_blank; return 1
  fi
  ui_blank
  ui_yesno 'Proceed?' y || { ui_info install "cancelled"; ui_blank; return 1; }
  ui_blank

  mkdir -p "$KESTREL_BIN_DIR"
  local log="$KESTREL_CONFIG_DIR/install.log"; mkdir -p "$KESTREL_CONFIG_DIR"; : > "$log"

  if [ ${#apt_items[@]} -gt 0 ]; then
    if sudo apt-get update >>"$log" 2>&1 && sudo apt-get install -y "${apt_items[@]}" >>"$log" 2>&1; then
      ui_ok apt "${apt_items[*]}"
    else ui_err apt "failed — see $log"; fi
  fi

  for t in "${go_items[@]}"; do
    name="${t%%|*}"
    if GOTOOLCHAIN=auto GOBIN="$KESTREL_BIN_DIR" CGO_ENABLED=1 go install -v "${t#*|}" >>"$log" 2>&1; then
      ui_ok "$name" "installed"
    else ui_err "$name" "go install failed — see $log"; fi
  done

  for t in "${script_items[@]}"; do
    case "$t" in
      trufflehog)
        if curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
             | sh -s -- -b "$KESTREL_BIN_DIR" >>"$log" 2>&1; then ui_ok trufflehog installed
        else ui_err trufflehog "install script failed — see $log"; fi ;;
    esac
  done

  # make sure the bin dir is on PATH
  case ":$PATH:" in
    *":$KESTREL_BIN_DIR:"*) : ;;
    *)
      local rc="$HOME/.bashrc"; case "${SHELL:-}" in *zsh) rc="$HOME/.zshrc" ;; esac
      ui_warn PATH "$KESTREL_BIN_DIR is not in \$PATH"
      if ui_yesno "Add it to $rc?" y; then
        printf '\n# kestrel tools\nexport PATH="%s:$PATH"\n' "$KESTREL_BIN_DIR" >> "$rc"
        ui_ok PATH "added — open a new terminal (or: source $rc)"
      fi
      export PATH="$KESTREL_BIN_DIR:$PATH" ;;
  esac

  # final check: every installed tool must answer from the shell
  ui_section check
  local bad=0
  for t in "$@"; do
    name="${t%%|*}"
    if tool_ok "$name"; then ui_ok "$name" "$(command -v "$name")"
    else ui_err "$name" "still missing"; bad=1; fi
  done
  ui_blank
  [ "$bad" -eq 0 ] && ui_next "kestrel new <program>" || ui_next "check $log"
  ui_blank
  return "$bad"
}
