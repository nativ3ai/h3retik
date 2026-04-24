#!/usr/bin/env bash
set -euo pipefail

ROOT="${H3RETIK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CONFIG_DIR="${H3RETIK_CONFIG_DIR:-$HOME/.config/h3retik}"
CONFIG_FILE="$CONFIG_DIR/setup.env"
SETUP_MARKER="$CONFIG_DIR/setup.complete"
KALI_CONTAINER_DEFAULT="${H3RETIK_KALI_CONTAINER:-h3retik-kali}"
KALI_IMAGE_DEFAULT="${H3RETIK_KALI_IMAGE:-h3retik/kali:v0.0.4}"

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

missing=()
ensure_bin docker || missing+=("docker")
ensure_bin python3 || missing+=("python3")
ensure_bin go || missing+=("go")

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

runtime_choice=$(ask_menu "Select runtime mode" \
  bundled "Bundled H3RETIK Kali container (recommended)" \
  attach "Attach TUI to an existing Kali container") || exit 1

kali_container="$KALI_CONTAINER_DEFAULT"
kali_image="$KALI_IMAGE_DEFAULT"
skip_up="0"

if [[ "$runtime_choice" == "attach" ]]; then
  kali_container=$(ask_input "Existing container name" "$KALI_CONTAINER_DEFAULT") || exit 1
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
CFG

if [[ "$runtime_choice" == "bundled" ]]; then
  show_info "Building/starting bundled runtime..."
  H3RETIK_KALI_CONTAINER="$kali_container" H3RETIK_KALI_IMAGE="$kali_image" "$ROOT/h3retik" up || true
fi

if ask_yes_no "Install optional bundles now? (You can also do this later with: h3retik tools install <bundle>)" "no"; then
  bundle=$(ask_menu "Choose optional bundle" \
    recon-plus "Recon Plus (masscan/rustscan/naabu/zmap/nbtscan/subfinder)" \
    web-adv-plus "Web Adv Plus (katana/gau/dalfox/httpx/jwt-tool)" \
    ad-plus "AD Plus (kerbrute/ldapdomaindump/certipy/evil-winrm)" \
    k8s-plus "K8S Plus (trivy/kubescape/kube-hunter)" \
    crack-plus "Crack Plus (hashcat/john)" \
    coop-plus "Co-op Plus (wildmesh)") || bundle=""
  if [[ -n "$bundle" ]]; then
    H3RETIK_KALI_CONTAINER="$kali_container" "$ROOT/h3retik" tools install "$bundle" || true
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
