#!/bin/bash
set -euo pipefail

############################################################
# Universal Raspberry Pi Setup Script
# Version: 2024-10-20-Enhanced
# Features: Multi-tier support, profiles, checkpointing,
#           temperature monitoring, piwheels, recovery,
#           static IP with conflict check, secure msmtp
############################################################

SCRIPT_VERSION="2024-10-20-Enhanced"
STATE_FILE="$HOME/.rpi_setup_state"
CHECKPOINT_FILE="$HOME/.rpi_setup_checkpoint"

############################################################
# Self-heal CRLF and support curl | bash execution
############################################################
fix_and_reexec() {
  local tmp
  tmp="$(mktemp)"
  tr -d '\r' < "$1" > "$tmp"
  chmod +x "$tmp"
  exec /bin/bash "$tmp" "$@"
}

if [ -n "${BASH_SOURCE[0]:-}" ] && [ -r "${BASH_SOURCE[0]}" ]; then
  if grep -q $'\r' "${BASH_SOURCE[0]}" 2>/dev/null; then
    echo "[INFO] Converting CRLF to LF and re-running..."
    fix_and_reexec "${BASH_SOURCE[0]}" "$@"
  fi
fi

############################################################
# Locale setup (defensive)
############################################################
setup_locale() {
  # Use a safe temporary locale during setup to avoid perl/apt warnings
  export LC_ALL=C.UTF-8
  export LANG=C.UTF-8

  sudo apt-get update -y
  sudo apt-get install -y locales

  # Ensure en_GB.UTF-8 is enabled
  if ! grep -qi '^en_GB\.UTF-8 UTF-8' /etc/locale.gen; then
    sudo sed -i 's/^# *en_GB\.UTF-8 UTF-8/en_GB.UTF-8 UTF-8/' /etc/locale.gen
    grep -q '^en_GB\.UTF-8 UTF-8' /etc/locale.gen || echo 'en_GB.UTF-8 UTF-8' | sudo tee -a /etc/locale.gen >/dev/null
  fi

  sudo locale-gen en_GB.UTF-8
  sudo update-locale LANG=en_GB.UTF-8 LC_ALL=en_GB.UTF-8

  # Switch this shell to the final locale
  export LANG=en_GB.UTF-8
  export LC_ALL=en_GB.UTF-8
}

############################################################
# Utilities and colours
############################################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()     { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success()  { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning()  { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()    { echo -e "${RED}[ERROR]${NC} $1" >&2; }
log_progress() { echo -e "${CYAN}[PROGRESS]${NC} $1"; }
log_temp()     { echo -e "${MAGENTA}[TEMP]${NC} $1"; }

# Robust TTY detection (works with curl | bash if </dev/tty provided)
IS_TTY=0
{ [ -t 0 ] || [ -t 1 ] || [ -t 2 ] || [ -r /dev/tty ]; } && IS_TTY=1

# Command line arguments
NON_INTERACTIVE=0
PRESET_TIER=""
PRESET_PROFILE=""
FORCE_RERUN=0

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --tier) PRESET_TIER="$2"; shift 2 ;;
    --profile) PRESET_PROFILE="$2"; shift 2 ;;
    --force) FORCE_RERUN=1; shift ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo "Options:"
      echo "  --non-interactive       Run without prompts (use defaults)"
      echo "  --tier TIER             MINIMAL/LOW/MEDIUM/HIGH"
      echo "  --profile PROFILE       generic/web/iot/media/dev"
      echo "  --force                 Force rerun"
      echo "  --help                  Show this help"
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"; exit 1 ;;
  esac
done

prompt_yn() {
  local question="$1" default="${2:-n}" ans
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    log_info "Non-interactive mode: defaulting '$question' to $default"
    ans="$default"
  elif [ "$IS_TTY" -eq 1 ]; then
    if [ -r /dev/tty ]; then read -r -p "$question" ans < /dev/tty || ans="$default"
    else read -r -p "$question" ans || ans="$default"; fi
  else
    log_info "Non-interactive mode: defaulting '$question' to $default"
    ans="$default"
  fi
  [[ "$ans" =~ ^[Yy]$ ]]
}

read_tty() {
  local prompt="$1" var
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    echo ""
  elif [ "$IS_TTY" -eq 1 ]; then
    if [ -r /dev/tty ]; then read -r -p "$prompt" var < /dev/tty
    else read -r -p "$prompt" var; fi
    echo "$var"
  else
    echo ""
  fi
}

if [ "$EUID" -eq 0 ]; then 
  log_error "Please do not run this script as root or with sudo"
  log_error "The script will prompt for sudo when needed"
  exit 1
fi

############################################################
# Temperature monitoring
############################################################
check_temperature() {
  if command -v vcgencmd &> /dev/null; then
    local temp_str temp temp_int
    temp_str=$(vcgencmd measure_temp 2>/dev/null || echo "temp=0.0'C")
    temp=$(echo "$temp_str" | grep -oP '\d+\.\d+' | head -1 || true)
    if [ -n "${temp:-}" ]; then
      temp_int=$(echo "$temp" | cut -d. -f1)
      if [ "$temp_int" -gt 80 ]; then
        log_temp "CPU Temperature: ${temp}°C - CRITICAL! Pausing for cooldown..."
        sleep 30; return 1
      elif [ "$temp_int" -gt 70 ]; then
        log_temp "CPU Temperature: ${temp}°C - High, slowing down..."
        sleep 10; return 0
      fi
    fi
  fi
  return 0
}

############################################################
# Checkpointing system
############################################################
save_checkpoint() { echo "$1" > "$CHECKPOINT_FILE"; log_progress "Checkpoint saved: $1"; }
load_checkpoint() { [ -f "$CHECKPOINT_FILE" ] && cat "$CHECKPOINT_FILE" || echo "START"; }
clear_checkpoint() { rm -f "$CHECKPOINT_FILE"; }

is_checkpoint_passed() {
  local checkpoint="$1" current; current=$(load_checkpoint)
  case "$current" in
    START) return 1 ;;
    LOCALE) [[ "$checkpoint" == "START" ]] ;;
    DETECT) [[ "$checkpoint" =~ ^(START|LOCALE)$ ]] ;;
    HOSTNAME) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT)$ ]] ;;
    NETWORK) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME)$ ]] ;;
    SWAP) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK)$ ]] ;;
    UPDATE) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP)$ ]] ;;
    UPGRADE) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP|UPDATE)$ ]] ;;
    ESSENTIAL) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP|UPDATE|UPGRADE)$ ]] ;;
    SECURITY) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP|UPDATE|UPGRADE|ESSENTIAL)$ ]] ;;
    GIT) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY)$ ]] ;;
    EMAIL) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|GIT)$ ]] ;;
    RASPI_CONFIG) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|GIT|EMAIL)$ ]] ;;
    PYTHON) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|GIT|EMAIL|RASPI_CONFIG)$ ]] ;;
    PROFILE) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|GIT|EMAIL|RASPI_CONFIG|PYTHON)$ ]] ;;
    ALIASES) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|HOSTNAME|NETWORK|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|GIT|EMAIL|RASPI_CONFIG|PYTHON|PROFILE)$ ]] ;;
    COMPLETE) return 0 ;;
    *) return 1 ;;
  esac
}

############################################################
# State management
############################################################
save_state() {
  cat > "$STATE_FILE" <<EOF
PI_MODEL=$PI_MODEL
PI_MEMORY=$PI_MEMORY
PI_ARCH=$PI_ARCH
PERF_TIER=$PERF_TIER
PROFILE=$PROFILE
HOSTNAME=$NEW_HOSTNAME
SERIAL=$PI_SERIAL
INSTALL_DATE=$(date +%Y-%m-%d)
SCRIPT_VERSION=$SCRIPT_VERSION
EOF
}

load_state() {
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE"
    return 0
  fi
  return 1
}

############################################################
# Detect Pi info
############################################################
detect_pi_info() {
  PI_MODEL="unknown"; PI_MEMORY=0; PI_ARCH=$(uname -m); PI_SERIAL="UNKNOWN"

  if [ -f /proc/cpuinfo ]; then
    PI_SERIAL=$(grep -m1 Serial /proc/cpuinfo | awk '{print $3}' | tail -c 9)
    [ -z "$PI_SERIAL" ] && PI_SERIAL="UNKNOWN"
  fi
  if [ -f /proc/device-tree/model ]; then
    MODEL_STRING=$(tr -d '\0' </proc/device-tree/model 2>/dev/null || true)
    case "$MODEL_STRING" in
      *"Pi Zero"*|*"Pi 0"*) PI_MODEL="0" ;;
      *"Compute Module 4"*) PI_MODEL="CM4" ;;
      *"Compute Module 3"*) PI_MODEL="CM3" ;;
      *"Compute Module"*) PI_MODEL="CM" ;;
      *"Pi 5"*) PI_MODEL="5" ;;
      *"Pi 4"*) PI_MODEL="4" ;;
      *"Pi 3"*) PI_MODEL="3" ;;
      *"Pi 2"*) PI_MODEL="2" ;;
      *"Pi 1"*|*"Model B Rev"*) PI_MODEL="1" ;;
    esac
  fi
  if [ -f /proc/meminfo ]; then
    MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    PI_MEMORY=$((MEM_KB / 1024))
  fi
  log_info "Detected: Pi $PI_MODEL, ${PI_MEMORY}MB RAM, $PI_ARCH, Serial: $PI_SERIAL"
}

############################################################
# Model / Tier / Profile
############################################################
set_performance_tier() {
  if [[ "$PI_MODEL" == "4" || "$PI_MODEL" == "5" ]]; then PERF_TIER="HIGH"
  elif [[ "$PI_MODEL" == "2" || "$PI_MODEL" == "3" ]]; then PERF_TIER="MEDIUM"
  elif [ "$PI_MEMORY" -le 512 ]; then PERF_TIER="LOW"
  else PERF_TIER="MEDIUM"; fi
  [ "$PI_MEMORY" -le 256 ] && PERF_TIER="MINIMAL"
}

PROFILE="generic"; PROFILE_ABBREV="GEN"
set_profile_abbrev() {
  case $PROFILE in
    generic) PROFILE_ABBREV="GEN" ;;
    web) PROFILE_ABBREV="WEB" ;;
    iot) PROFILE_ABBREV="IOT" ;;
    media) PROFILE_ABBREV="MED" ;;
    dev) PROFILE_ABBREV="DEV" ;;
    *) PROFILE_ABBREV="GEN" ;;
  esac
}

select_pi_model() {
  if [ -n "$PRESET_TIER" ]; then
    PERF_TIER="$PRESET_TIER"; log_info "Using preset tier: $PERF_TIER"; return
  fi
  echo ""; echo "=========================================="
  echo "Select Your Raspberry Pi Model"
  echo "=========================================="
  echo "Auto-detected: Pi $PI_MODEL with ${PI_MEMORY}MB RAM"
  echo ""; echo "1) Pi Zero/Zero W"; echo "2) Pi 1"; echo "3) Pi 2"; echo "4) Pi 3"; echo "5) Pi 4"
  echo "6) Use auto-detected values"; echo "7) Manual override"; echo ""
  local choice; choice=$(read_tty "Enter choice [1-7] (default: 6): "); choice=${choice:-6}
  case $choice in
    1) PI_MODEL="0"; PI_MEMORY=512; PI_ARCH="armv6l" ;;
    2) PI_MODEL="1"; PI_MEMORY=$(read_tty "Memory [256/512] (default: 512): "); PI_MEMORY=${PI_MEMORY:-512}; PI_ARCH="armv6l" ;;
    3) PI_MODEL="2"; PI_MEMORY=1024; PI_ARCH="armv7l" ;;
    4) PI_MODEL="3"; PI_MEMORY=1024; PI_ARCH="armv8" ;;
    5) PI_MODEL="4"; local mem_choice; mem_choice=$(read_tty "RAM [1024/2048/4096/8192] (default: 2048): "); PI_MEMORY=${mem_choice:-2048}; PI_ARCH="armv8" ;;
    6) log_info "Using auto-detected values" ;;
    7) PI_MODEL=$(read_tty "Enter Pi model (0/1/2/3/4/5): ")
       PI_MEMORY=$(read_tty "Enter RAM in MB: ")
       PI_ARCH=$(read_tty "Enter architecture (armv6l/armv7l/armv8): ") ;;
    *) log_warning "Invalid choice, using auto-detected values" ;;
  esac
  set_performance_tier
  echo ""; log_info "Configuration: Pi $PI_MODEL, ${PI_MEMORY}MB RAM, $PI_ARCH"
  log_info "Performance tier: $PERF_TIER"; log_info "Serial: $PI_SERIAL"; echo ""
}

select_profile() {
  if [ -n "$PRESET_PROFILE" ]; then PROFILE="$PRESET_PROFILE"; set_profile_abbrev; log_info "Using preset profile: $PROFILE ($PROFILE_ABBREV)"; return; fi
  echo ""; echo "=========================================="; echo "Select Installation Profile"; echo "=========================================="
  echo "1) Generic (GEN)"; echo "2) Web Server (WEB)"; echo "3) IoT Sensor (IOT)"; echo "4) Media Center (MED)"; echo "5) Development (DEV)"; echo ""
  local choice; choice=$(read_tty "Enter choice [1-5] (default: 1): "); choice=${choice:-1}
  case $choice in
    1) PROFILE="generic" ;; 2) PROFILE="web" ;; 3) PROFILE="iot" ;; 4) PROFILE="media" ;; 5) PROFILE="dev" ;; *) PROFILE="generic" ;;
  esac; set_profile_abbrev; log_info "Selected profile: $PROFILE ($PROFILE_ABBREV)"
}

############################################################
# Hostname configuration
############################################################
set_hostname() {
  NEW_HOSTNAME="LH-PI${PI_MODEL}-${PI_SERIAL}-${PROFILE_ABBREV}"
  CURRENT_HOSTNAME=$(hostname)
  log_info "Current hostname: $CURRENT_HOSTNAME"
  log_info "Proposed hostname: $NEW_HOSTNAME"
  if [ "$CURRENT_HOSTNAME" = "$NEW_HOSTNAME" ]; then log_info "Hostname already set correctly"; return; fi
  if prompt_yn "Set hostname to $NEW_HOSTNAME? (y/n): " y; then
    echo "$NEW_HOSTNAME" | sudo tee /etc/hostname >/dev/null
    sudo sed -i "s/127.0.1.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
    sudo hostnamectl set-hostname "$NEW_HOSTNAME" 2>/dev/null || true
    log_success "Hostname set to $NEW_HOSTNAME (takes effect after reboot)"
  else
    NEW_HOSTNAME="$CURRENT_HOSTNAME"; log_info "Keeping current hostname"
  fi
}

############################################################
# Network helpers (static IP with conflict check)
############################################################
nm_available() { command -v nmcli >/dev/null 2>&1 && systemctl is-active --quiet NetworkManager 2>/dev/null; }
get_default_iface() { ip route 2>/dev/null | awk '/^default/ {print $5; exit}'; }
list_ipv4_ifaces() { ip -o -4 addr show | awk '{print $2}' | sort -u | grep -v '^lo$' || true; }
iface_current_cidr() { local ifc="$1"; ip -o -4 addr show dev "$ifc" | awk '{print $4}' | head -1; }
iface_current_gw() { ip route | awk '/^default/ {print $3; exit}'; }
is_ip_in_use() {
  local ip="$1" ifc="${2:-}"
  ping -c1 -W1 "$ip" >/dev/null 2>&1 && return 0
  if command -v arping >/dev/null 2>&1; then
    if [ -n "$ifc" ]; then sudo arping -D -c 2 -w 2 -I "$ifc" "$ip" >/dev/null 2>&1 && return 0
    else sudo arping -D -c 2 -w 2 "$ip" >/dev/null 2>&1 && return 0; fi
  fi
  return 1
}
write_dhcpcd_static() {
  local ifc="$1" cidr="$2" gw="$3" dns="$4"
  local conf="/etc/dhcpcd.conf" tmp
  tmp=$(sudo mktemp /tmp/dhcpcd.conf.mml.XXXXXX)
  if sudo test -r "$conf"; then
    sudo awk '
      BEGIN{skip=0}
      /# >>> mml_rpi_setup static/ {skip=1; next}
      /# <<< mml_rpi_setup static/ {skip=0; next}
      skip==0 {print}
    ' "$conf" | sudo tee "$tmp" >/dev/null
  else
    : | sudo tee "$tmp" >/dev/null
  fi
  sudo bash -c "cat >> '$tmp' <<EOF
# >>> mml_rpi_setup static
interface $ifc
static ip_address=$cidr
static routers=$gw
static domain_name_servers=$dns
# <<< mml_rpi_setup static
EOF"
  sudo mv "$tmp" "$conf"
  sudo systemctl restart dhcpcd || true
}
remove_dhcpcd_static() {
  local conf="/etc/dhcpcd.conf" tmp
  sudo test -r "$conf" || return 0
  tmp=$(sudo mktemp /tmp/dhcpcd.conf.mml.XXXXXX)
  sudo awk '
    BEGIN{skip=0}
    /# >>> mml_rpi_setup static/ {skip=1; next}
    /# <<< mml_rpi_setup static/ {skip=0; next}
    skip==0 {print}
  ' "$conf" | sudo tee "$tmp" >/dev/null
  sudo mv "$tmp" "$conf"
  sudo systemctl restart dhcpcd || true
}
configure_static_nm() {
  local ifc="$1" cidr="$2" gw="$3" dns="$4" conn
  conn=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v IF="$ifc" '$2==IF{print $1; exit}')
  [ -z "$conn" ] && conn="$ifc"
  sudo nmcli con mod "$conn" ipv4.method manual ipv4.addresses "$cidr" ipv4.gateway "$gw" ipv4.dns "$dns" ipv6.method ignore
  sudo nmcli con up "$conn" || sudo nmcli dev reapply "$ifc" || true
}
configure_dhcp_nm() {
  local ifc="$1" conn
  conn=$(nmcli -t -f NAME,DEVICE con show --active | awk -F: -v IF="$ifc" '$2==IF{print $1; exit}')
  [ -z "$conn" ] && conn="$ifc"
  sudo nmcli con mod "$conn" ipv4.method auto ipv6.method ignore
  sudo nmcli con up "$conn" || sudo nmcli dev reapply "$ifc" || true
}
configure_network() {
  if ! prompt_yn "Would you like to set a static IPv4 address? (y/n): " n; then
    log_info "Keeping DHCP configuration"; return
  fi
  local default_ifc ifaces ifc
  default_ifc="$(get_default_iface)"
  mapfile -t ifaces < <(list_ipv4_ifaces)
  ifc="$default_ifc"
  if [ "${#ifaces[@]}" -gt 1 ]; then
    echo "Available interfaces: ${ifaces[*]}"
    local sel; sel=$(read_tty "Choose interface (default: $default_ifc): "); ifc="${sel:-$default_ifc}"
  fi
  [ -z "$ifc" ] && { log_warning "No IPv4 interface found; skipping static IP setup."; return; }

  local current_cidr current_gw def_dns cidr_in gw_in dns_in ip_only
  current_cidr="$(iface_current_cidr "$ifc")"; current_gw="$(iface_current_gw)"; def_dns="1.1.1.1 8.8.8.8"

  echo ""; log_info "Enter the static IP details for interface: $ifc"
  log_info "Use CIDR notation (e.g. 192.168.1.50/24)"
  cidr_in=$(read_tty "Static IP (CIDR) [default: ${current_cidr%/*}/24 if unknown]: ")
  if [ -z "$cidr_in" ]; then
    if [[ "$current_cidr" =~ /[0-9]+$ ]]; then cidr_in="${current_cidr%/*}/${current_cidr#*/}"
    else cidr_in="$(hostname -I | awk '{print $1}')/24"; fi
  fi
  gw_in=$(read_tty "Gateway [default: $current_gw]: "); gw_in="${gw_in:-$current_gw}"
  dns_in=$(read_tty "DNS servers space-separated [default: $def_dns]: "); dns_in="${dns_in:-$def_dns}"
  ip_only="${cidr_in%%/*}"

  log_info "Checking if $ip_only is already in use on the network..."
  if is_ip_in_use "$ip_only" "$ifc"; then
    log_warning "Address $ip_only appears to be in use. Falling back to DHCP."
    if nm_available; then configure_dhcp_nm "$ifc"; else remove_dhcpcd_static; fi
    return
  fi

  if nm_available; then
    log_info "Configuring static IP via NetworkManager..."
    configure_static_nm "$ifc" "$cidr_in" "$gw_in" "$dns_in"
  else
    log_info "Configuring static IP via dhcpcd..."
    write_dhcpcd_static "$ifc" "$cidr_in" "$gw_in" "$dns_in"
  fi

  sleep 2
  ip -4 addr show dev "$ifc" | grep -q "$ip_only" \
    && log_success "Static IP $cidr_in set on $ifc" \
    || log_warning "Could not verify static IP on $ifc. Network may need a reboot or replug."
}

############################################################
# Swap setup
############################################################
setup_swap() {
  if [ "$PI_MEMORY" -le 512 ]; then
    log_info "Low memory detected (${PI_MEMORY}MB). Checking swap..."
    local current_swap; current_swap=$(free -m | awk '/^Swap:/ {print $2}')
    if [ "$current_swap" -lt 1024 ]; then
      log_warning "Current swap is ${current_swap}MB"
      if prompt_yn "Increase swap to 1024MB for package compilation? (y/n): " y; then
        log_info "Setting up swap file..."
        sudo dphys-swapfile swapoff 2>/dev/null || true
        sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile 2>/dev/null || echo "CONF_SWAPSIZE=1024" | sudo tee -a /etc/dphys-swapfile >/dev/null
        sudo dphys-swapfile setup
        sudo dphys-swapfile swapon
        log_success "Swap increased to 1024MB"
      fi
    else
      log_info "Swap already adequate (${current_swap}MB)"
    fi
  fi
}

############################################################
# Piwheels configuration
############################################################
setup_piwheels() {
  log_info "Configuring piwheels for faster Python package installation..."
  mkdir -p ~/.pip
  if [ ! -f ~/.pip/pip.conf ] || ! grep -q "piwheels" ~/.pip/pip.conf; then
    cat > ~/.pip/pip.conf <<'EOF'
[global]
extra-index-url=https://www.piwheels.org/simple
EOF
    log_success "Piwheels configured in ~/.pip/pip.conf"
  else
    log_info "Piwheels already configured"
  fi
}

############################################################
# Progress indicator
############################################################
show_progress() {
  local duration=$1 message=$2 elapsed=0
  while [ $elapsed -lt $duration ]; do
    printf "\r${CYAN}[PROGRESS]${NC} %s... %d/%d seconds" "$message" "$elapsed" "$duration"
    sleep 5; elapsed=$((elapsed + 5)); check_temperature || sleep 20
  done
  printf "\r${CYAN}[PROGRESS]${NC} %s... Complete!          \n" "$message"
}

############################################################
# Main banner
############################################################
clear
echo "=========================================="
echo "Universal Raspberry Pi Setup Script"
echo "Version: $SCRIPT_VERSION"
echo "=========================================="
echo ""

# Recovery / resume
LAST_CHECKPOINT=$(load_checkpoint)
if [ "$LAST_CHECKPOINT" != "START" ] && [ "$LAST_CHECKPOINT" != "COMPLETE" ] && [ "$FORCE_RERUN" -eq 0 ]; then
  log_warning "Previous installation was interrupted at: $LAST_CHECKPOINT"
  if prompt_yn "Resume from last checkpoint? (y/n): " y; then
    log_info "Resuming from checkpoint: $LAST_CHECKPOINT"
  else
    log_info "Starting fresh installation"; clear_checkpoint; LAST_CHECKPOINT="START"
  fi
else
  LAST_CHECKPOINT="START"
fi

# Already completed?
if load_state && [ "$FORCE_RERUN" -eq 0 ]; then
  log_info "Previous installation detected:"
  log_info "  Profile: $PROFILE ($PROFILE_ABBREV)"
  log_info "  Tier: $PERF_TIER"
  log_info "  Hostname: $HOSTNAME"
  log_info "  Date: $INSTALL_DATE"
  echo ""
  if prompt_yn "Would you like to switch to a different profile? (y/n): " n; then
    log_info "Profile switching mode activated"
    detect_pi_info; select_profile
    if [ "$PROFILE" != "$(grep PROFILE= "$STATE_FILE" | cut -d= -f2)" ]; then
      log_info "Switching to profile: $PROFILE"; LAST_CHECKPOINT="PROFILE"
    else
      log_info "Same profile selected, no changes needed"; exit 0
    fi
  else
    log_info "Setup already completed. Use --force to rerun"; exit 0
  fi
fi

############################################################
# Locale
############################################################
if ! is_checkpoint_passed "LOCALE"; then
  setup_locale; save_checkpoint "LOCALE"
fi

############################################################
# Detection
############################################################
if ! is_checkpoint_passed "DETECT"; then
  detect_pi_info
  if [ -f /proc/device-tree/model ]; then
    if grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
      log_info "Confirmed Raspberry Pi detected"
    else
      log_warning "This doesn't appear to be a Raspberry Pi"
      if ! prompt_yn "Continue anyway? (y/n): " n; then log_info "Setup cancelled"; exit 0; fi
    fi
  fi
  select_pi_model; select_profile; save_checkpoint "DETECT"
fi

############################################################
# Hostname
############################################################
if ! is_checkpoint_passed "HOSTNAME"; then
  set_hostname; save_checkpoint "HOSTNAME"
fi

############################################################
# Network (Static IP selection)
############################################################
if ! is_checkpoint_passed "NETWORK"; then
  configure_network; save_checkpoint "NETWORK"
fi

############################################################
# Swap
############################################################
if ! is_checkpoint_passed "SWAP"; then
  if [[ "$PERF_TIER" == "LOW" || "$PERF_TIER" == "MINIMAL" ]]; then setup_swap; fi
  save_checkpoint "SWAP"
fi

############################################################
# System update
############################################################
if ! is_checkpoint_passed "UPDATE"; then
  log_info "Updating package lists..."
  if ! sudo apt-get update -y; then log_error "Failed to update package lists"; exit 1; fi
  save_checkpoint "UPDATE"
fi

############################################################
# System upgrade
############################################################
if ! is_checkpoint_passed "UPGRADE"; then
  if [[ "$PERF_TIER" == "MINIMAL" ]]; then
    log_warning "Very low memory detected. Upgrade will be slow."
    if ! prompt_yn "Proceed with full system upgrade? (y/n): " y; then
      log_info "Skipping upgrade. You can run 'sudo apt upgrade' later."; save_checkpoint "UPGRADE"
    else
      log_info "Upgrading packages..."; (sudo apt-get upgrade -y &) && show_progress 3600 "Upgrading system packages"; wait; save_checkpoint "UPGRADE"
    fi
  else
    log_info "Upgrading installed packages (this may take a while)..."
    if [[ "$PERF_TIER" == "LOW" ]]; then (sudo apt-get upgrade -y &) && show_progress 1800 "Upgrading system packages"; wait
    else sudo apt-get upgrade -y; fi
    save_checkpoint "UPGRADE"
  fi
  check_temperature
fi

############################################################
# Essential packages
############################################################
if ! is_checkpoint_passed "ESSENTIAL"; then
  log_info "Installing essential packages for $PERF_TIER tier system..."
  ESSENTIAL_PACKAGES=(curl wget git vim htop tree unzip apt-transport-https ca-certificates gnupg lsb-release net-tools ufw)
  # (optional, for better IP conflict check)
  ESSENTIAL_PACKAGES+=(arping)
  [[ "$PERF_TIER" != "MINIMAL" ]] && ESSENTIAL_PACKAGES+=(build-essential)
  if [[ "$PERF_TIER" == "HIGH" || "$PERF_TIER" == "MEDIUM" ]]; then
    ESSENTIAL_PACKAGES+=(python3-pip python3-venv python3-dev)
  elif [[ "$PERF_TIER" == "LOW" ]]; then
    ESSENTIAL_PACKAGES+=(python3-pip python3-venv)
  else
    ESSENTIAL_PACKAGES+=(python3)
  fi
  if [[ "$PERF_TIER" == "HIGH" || "$PERF_TIER" == "MEDIUM" ]]; then
    if [[ "$PI_ARCH" != "armv6l" ]]; then
      if prompt_yn "Install Node.js and npm? (not recommended for ARMv6) (y/n): " n; then ESSENTIAL_PACKAGES+=(nodejs npm); fi
    fi
  fi
  if ! sudo apt-get install -y "${ESSENTIAL_PACKAGES[@]}"; then log_error "Failed to install essential packages"; exit 1; fi
  log_success "Essential packages installed"; save_checkpoint "ESSENTIAL"; check_temperature
fi

############################################################
# Security setup
############################################################
if ! is_checkpoint_passed "SECURITY"; then
  log_info "Setting up basic firewall (UFW)..."
  sudo ufw --force enable
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow ssh
  log_success "Firewall configured (SSH allowed)"
  if ! systemctl is-active --quiet ssh; then
    log_info "Enabling SSH service..."; sudo systemctl enable --now ssh; log_success "SSH enabled and started"
  else
    log_info "SSH service already running"
  fi
  save_checkpoint "SECURITY"
fi

############################################################
# Git setup
############################################################
if ! is_checkpoint_passed "GIT"; then
  if prompt_yn "Would you like to configure Git? (y/n): " n; then
    git_username=$(read_tty "Enter your Git username: ")
    git_email=$(read_tty "Enter your Git email: ")
    if [ -n "$git_username" ] && [ -n "$git_email" ]; then
      git config --global user.name "$git_username"
      git config --global user.email "$git_email"
      git config --global init.defaultBranch main
      git config --global pull.rebase false
      log_success "Git configured successfully"
    else
      log_warning "Git configuration skipped (empty values)"
    fi
  fi
  save_checkpoint "GIT"
fi

############################################################
# Email setup (secure with GPG + passwordeval)
############################################################
if ! is_checkpoint_passed "EMAIL"; then
  if [ -f ~/.msmtprc ]; then
    log_info "Email (msmtp) already configured"
    if prompt_yn "Would you like to reconfigure email? (y/n): " n; then
      rm -f ~/.msmtprc ~/.secrets/msmtp.gpg
    fi
  fi

  if [ ! -f ~/.msmtprc ]; then
    if prompt_yn "Would you like to configure email (msmtp)? (y/n): " n; then
      log_info "Installing msmtp and gpg..."
      sudo apt-get install -y msmtp msmtp-mta gpg
      mkdir -p ~/.secrets && chmod 700 ~/.secrets

      email_address=$(read_tty "Enter your Gmail address: ")
      if [ -n "$email_address" ]; then
        log_warning "You need a Gmail App Password (not your regular password)"
        log_info "Create one at: https://myaccount.google.com/apppasswords"

        printf "Enter your Gmail App Password (16 chars, no spaces): " > /dev/tty
        stty -echo; read -r app_password < /dev/tty || app_password=""; stty echo; echo > /dev/tty

        if [ -n "$app_password" ]; then
          printf "%s" "$app_password" | gpg --symmetric --cipher-algo AES256 -o ~/.secrets/msmtp.gpg
          chmod 600 ~/.secrets/msmtp.gpg
          unset app_password

          cat > ~/.msmtprc <<EOF
defaults
auth           on
tls            on
tls_starttls   on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        ~/.msmtp.log

account        gmail
host           smtp.gmail.com
port           587
from           $email_address
user           $email_address
passwordeval   "gpg --quiet --batch --decrypt ~/.secrets/msmtp.gpg"

account default : gmail
EOF
          chmod 600 ~/.msmtprc

          log_info "Testing email configuration..."
          if echo "Test email from Raspberry Pi $(hostname)" | msmtp "$email_address" 2>/dev/null; then
            log_success "Email configured and tested successfully!"
            log_info "Check your inbox (or spam folder) for the test email"
          else
            log_warning "Email configured but test failed - check ~/.msmtp.log for details"
            log_info "You can test manually with: echo 'test' | msmtp $email_address"
          fi
        else
          log_warning "Email configuration skipped (no app password provided)"
        fi
      else
        log_warning "Email configuration skipped (no email address provided)"
      fi
    fi
  fi
  save_checkpoint "EMAIL"
fi

############################################################
# Raspi-config
############################################################
if ! is_checkpoint_passed "RASPI_CONFIG"; then
  if command -v raspi-config &> /dev/null; then
    log_info "Expanding filesystem to use full SD card..."
    if sudo raspi-config nonint do_expand_rootfs; then log_success "Filesystem expansion configured (reboot required)"; else log_warning "Expansion may have already been performed"; fi

    if prompt_yn "Allocate GPU memory? (y/n): " n; then
      local gpu_mem
      if [[ "$PERF_TIER" == "MINIMAL" || "$PERF_TIER" == "LOW" ]]; then
        gpu_mem=$(read_tty "GPU memory in MB [16/32/64] (default: 16): "); gpu_mem=${gpu_mem:-16}
      else
        gpu_mem=$(read_tty "GPU memory in MB [64/128/256] (default: 128): "); gpu_mem=${gpu_mem:-128}
      fi
      if ! grep -q "^gpu_mem=" /boot/config.txt 2>/dev/null && ! grep -q "^gpu_mem=" /boot/firmware/config.txt 2>/dev/null; then
        if [ -f /boot/firmware/config.txt ]; then echo "gpu_mem=$gpu_mem" | sudo tee -a /boot/firmware/config.txt >/dev/null
        else echo "gpu_mem=$gpu_mem" | sudo tee -a /
