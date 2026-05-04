#!/usr/bin/env bash
set -euo pipefail

ROOT="${H3RETIK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CONFIG_DIR="${H3RETIK_CONFIG_DIR:-$HOME/.config/h3retik}"
CONFIG_FILE="$CONFIG_DIR/setup.env"
SETUP_MARKER="$CONFIG_DIR/setup.complete"
KALI_CONTAINER_DEFAULT="${H3RETIK_KALI_CONTAINER:-h3retik-kali}"
KALI_IMAGE_DEFAULT="${H3RETIK_KALI_IMAGE:-h3retik/kali:v0.0.5}"

mkdir -p "$CONFIG_DIR"

ui_mode="plain"
if command -v whiptail >/dev/null 2>&1; then
  ui_mode="whiptail"
elif command -v dialog >/dev/null 2>&1; then
  ui_mode="dialog"
fi

say() {
  printf '%s\n' "$*"
}

show_info() {
  local text="$1"
  if [[ "$ui_mode" == "whiptail" ]]; then
    whiptail --title "h3retik setup" --msgbox "$text" 20 78
  elif [[ "$ui_mode" == "dialog" ]]; then
    dialog --title "h3retik setup" --msgbox "$text" 20 78
    clear
  else
    say ""
    say "$text"
    say ""
  fi
}

ask_yes_no() {
  local prompt="$1"
  local default_yes="${2:-yes}"
  if [[ "$ui_mode" == "whiptail" ]]; then
    if [[ "$default_yes" == "yes" ]]; then
      whiptail --title "h3retik setup" --defaultno --yesno "$prompt" 12 78
      return $?
    fi
    whiptail --title "h3retik setup" --yesno "$prompt" 12 78
    return $?
  elif [[ "$ui_mode" == "dialog" ]]; then
    if [[ "$default_yes" == "yes" ]]; then
      dialog --title "h3retik setup" --defaultno --yesno "$prompt" 12 78
    else
      dialog --title "h3retik setup" --yesno "$prompt" 12 78
    fi
    local rc=$?
    clear
    return $rc
  else
    local hint="Y/n"
    [[ "$default_yes" == "no" ]] && hint="y/N"
    read -r -p "$prompt [$hint]: " reply
    reply="${reply:-}"
    if [[ -z "$reply" ]]; then
      [[ "$default_yes" == "yes" ]] && return 0 || return 1
    fi
    case "${reply,,}" in
      y|yes) return 0 ;;
      *) return 1 ;;
    esac
  fi
}

ask_input() {
  local prompt="$1"
  local default_val="${2:-}"
  local value=""
  if [[ "$ui_mode" == "whiptail" ]]; then
    value=$(whiptail --title "h3retik setup" --inputbox "$prompt" 12 90 "$default_val" 3>&1 1>&2 2>&3) || return 1
    printf '%s' "$value"
  elif [[ "$ui_mode" == "dialog" ]]; then
    value=$(dialog --title "h3retik setup" --inputbox "$prompt" 12 90 "$default_val" 3>&1 1>&2 2>&3) || return 1
    clear
    printf '%s' "$value"
  else
    read -r -p "$prompt [$default_val]: " value
    printf '%s' "${value:-$default_val}"
  fi
}

ask_menu() {
  local prompt="$1"
  shift
  local items=("$@")
  local value=""
  if [[ "$ui_mode" == "whiptail" ]]; then
    value=$(whiptail --title "h3retik setup" --menu "$prompt" 20 100 8 "${items[@]}" 3>&1 1>&2 2>&3) || return 1
    printf '%s' "$value"
  elif [[ "$ui_mode" == "dialog" ]]; then
    value=$(dialog --title "h3retik setup" --menu "$prompt" 20 100 8 "${items[@]}" 3>&1 1>&2 2>&3) || return 1
    clear
    printf '%s' "$value"
  else
    say "$prompt"
    local idx=1
    local map=()
    while [[ $# -gt 0 ]]; do
      local key="$1"; shift
      local desc="$1"; shift
      say "  $idx) $desc"
      map+=("$key")
      idx=$((idx+1))
    done
    local choice
    read -r -p "Select number: " choice
    [[ "$choice" =~ ^[0-9]+$ ]] || return 1
    local pos=$((choice-1))
    [[ $pos -ge 0 && $pos -lt ${#map[@]} ]] || return 1
    printf '%s' "${map[$pos]}"
  fi
}

ask_checklist() {
  local prompt="$1"
  shift
  local items=("$@")
  local value=""
  if [[ "$ui_mode" == "whiptail" ]]; then
    value=$(whiptail --title "h3retik setup" --checklist "$prompt" 22 110 12 "${items[@]}" 3>&1 1>&2 2>&3) || return 1
    value="${value//\"/}"
    printf '%s' "$value"
  elif [[ "$ui_mode" == "dialog" ]]; then
    value=$(dialog --title "h3retik setup" --checklist "$prompt" 22 110 12 "${items[@]}" 3>&1 1>&2 2>&3) || return 1
    clear
    value="${value//\"/}"
    printf '%s' "$value"
  else
    say "$prompt"
    local idx=1
    local keys=()
    while [[ $# -gt 0 ]]; do
      local key="$1"; shift
      local desc="$1"; shift
      shift # status
      say "  $idx) $desc [$key]"
      keys+=("$key")
      idx=$((idx+1))
    done
    local raw
    read -r -p "Select one or more numbers (comma-separated, blank to skip): " raw
    raw="${raw// /}"
    [[ -n "$raw" ]] || return 0
    local out=()
    IFS=',' read -r -a picks <<< "$raw"
    for p in "${picks[@]}"; do
      [[ "$p" =~ ^[0-9]+$ ]] || continue
      local pos=$((p-1))
      if [[ $pos -ge 0 && $pos -lt ${#keys[@]} ]]; then
        out+=("${keys[$pos]}")
      fi
    done
    printf '%s' "${out[*]}"
  fi
}

ensure_bin() {
  local bin="$1"
  command -v "$bin" >/dev/null 2>&1
}

try_install_go() {
  if ensure_bin go; then
    return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    brew install go && return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y golang-go && return 0
  fi
  return 1
}

try_install_python() {
  if ensure_bin python3; then
    return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    brew install python@3.12 && return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y python3 && return 0
  fi
  return 1
}

try_install_docker() {
  if ensure_bin docker; then
    return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    brew install --cask docker && return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin && return 0
  fi
  return 1
}

show_info "H3RETIK guided setup\n\nThis wizard configures runtime, dependencies, and optional tool bundles.\nYou can always rerun with: h3retik setup"
show_info "Go requirement clarity:\n- Go is needed only to compile juicetui when no prebuilt binary is available.\n- If a prebuilt bin/juicetui exists, H3RETIK can run without Go.\n- Recommended: keep Go installed for h3retik build/update resilience."

runtime_choice=$(ask_menu "Select runtime mode" \
  bundled "Bundled H3RETIK Kali container (recommended)" \
  attach "Attach TUI to an existing Kali container" \
  local "Local tools only (no Kali container)") || exit 1

missing=()
if ensure_bin python3; then :; else missing+=("python3"); fi
if ensure_bin go; then :; else missing+=("go"); fi
if [[ "$runtime_choice" != "local" ]]; then
  if ensure_bin docker; then :; else missing+=("docker"); fi
fi

if [[ ${#missing[@]} -gt 0 ]]; then
  show_info "Missing dependencies detected: ${missing[*]}"
  if ask_yes_no "Attempt auto-install of missing dependencies now?" "yes"; then
    for dep in "${missing[@]}"; do
      case "$dep" in
        docker)
          try_install_docker || show_info "Could not auto-install docker. Install it manually and re-run setup."
          ;;
        python3)
          try_install_python || show_info "Could not auto-install python3. Install it manually and re-run setup."
          ;;
        go)
          try_install_go || show_info "Could not auto-install go. Install it manually and re-run setup."
          ;;
      esac
    done
  fi
fi

kali_container="$KALI_CONTAINER_DEFAULT"
kali_image="$KALI_IMAGE_DEFAULT"
skip_up="0"

if [[ "$runtime_choice" == "attach" ]]; then
  kali_container=$(ask_input "Existing container name" "$KALI_CONTAINER_DEFAULT") || exit 1
  skip_up="1"
elif [[ "$runtime_choice" == "local" ]]; then
  skip_up="1"
else
  kali_container=$(ask_input "Bundled container name" "$KALI_CONTAINER_DEFAULT") || exit 1
  kali_image=$(ask_input "Kali image tag" "$KALI_IMAGE_DEFAULT") || exit 1
fi

cat > "$CONFIG_FILE" <<CFG
# Generated by h3retik setup wizard
export H3RETIK_CONFIG_DIR="$CONFIG_DIR"
export H3RETIK_KALI_CONTAINER="$kali_container"
export H3RETIK_KALI_IMAGE="$kali_image"
export H3RETIK_RUNTIME_MODE="$runtime_choice"
CFG

if [[ "$runtime_choice" == "bundled" ]]; then
  show_info "Building/starting bundled runtime..."
  H3RETIK_KALI_CONTAINER="$kali_container" H3RETIK_KALI_IMAGE="$kali_image" "$ROOT/h3retik" up || true
fi

install_spec=""
if ask_yes_no "Configure tool footprint now? (Lite/custom/full modular install)" "yes"; then
  profile=$(ask_menu "Choose installation profile" \
    minimal "Minimal (base runtime only)" \
    local-lite "Lite preset: local exploit lane only (local-plus)" \
    web-lite "Lite preset: web lane only (recon-plus + web-adv-plus)" \
    full "Full preset: all bundled lane packs" \
    custom-bundles "Custom: choose bundled packs" \
    custom-tools "Custom: enter individual tool names") || profile="minimal"
  case "$profile" in
    minimal)
      install_spec=""
      ;;
    local-lite)
      install_spec="local-plus"
      ;;
    web-lite)
      install_spec="recon-plus,web-adv-plus"
      ;;
    full)
      install_spec="recon-plus,web-adv-plus,ad-plus,k8s-plus,crack-plus,coop-plus,local-plus"
      ;;
    custom-bundles)
      selected="$(ask_checklist "Select one or more bundle packs" \
        recon-plus "Recon Plus (masscan/rustscan/naabu/zmap/nbtscan/subfinder)" OFF \
        web-adv-plus "Web Adv Plus (katana/gau/dalfox/httpx/jwt-tool)" OFF \
        ad-plus "AD Plus (kerbrute/ldapdomaindump/certipy/evil-winrm)" OFF \
        k8s-plus "K8S Plus (trivy/kubescape/kube-hunter)" OFF \
        crack-plus "Crack Plus (hashcat/john)" OFF \
        coop-plus "Co-op Plus (wildmesh)" OFF \
        local-plus "Local Plus (linpeas/lse/pspy/semgrep/gitleaks/trivy/grype)" OFF)" || selected=""
      if [[ -n "$selected" ]]; then
        install_spec="$(echo "$selected" | tr ' ' ',' | sed 's/,,*/,/g; s/^,//; s/,$//')"
      fi
      ;;
    custom-tools)
      install_spec="$(ask_input "Enter comma-separated individual tools (example: nmap,ffuf,sqlmap,semgrep)" "")" || install_spec=""
      install_spec="$(echo "$install_spec" | tr -d ' ' | sed 's/,,*/,/g; s/^,//; s/,$//')"
      ;;
  esac
fi

if [[ -n "$install_spec" ]]; then
  if [[ "$runtime_choice" == "local" ]]; then
    show_info "Tool install into Kali runtime is unavailable in local mode. Saved no runtime install.\nYou can still register local tools with:\n  h3retik modules add-local-tool ..."
  else
    H3RETIK_KALI_CONTAINER="$kali_container" "$ROOT/h3retik" tools install "$install_spec" || true
  fi
fi

touch "$SETUP_MARKER"

show_info "Setup complete.\n\nRuntime mode: $runtime_choice\nContainer: $kali_container\n\nNext:\n  h3retik\n  h3retik doctor"

if ask_yes_no "Launch H3RETIK TUI now?" "yes"; then
  if [[ "$skip_up" == "1" ]]; then
    export H3RETIK_SKIP_UP=1
  fi
  export H3RETIK_KALI_CONTAINER="$kali_container"
  export H3RETIK_KALI_IMAGE="$kali_image"
  exec "$ROOT/h3retik" tui
fi
