#!/bin/bash
set -euo pipefail

############################################################
# Universal Raspberry Pi Setup Script
# Version: 2024-10-20-Secure
# Features: Enhanced security, validation, VNC support,
#           proper error handling, and comprehensive logging
############################################################

SCRIPT_VERSION="2024-10-20-Secure"
SCRIPT_HASH="PLACEHOLDER_HASH"

# File paths
STATE_FILE="$HOME/.rpi_setup_state"
CHECKPOINT_FILE="$HOME/.rpi_setup_checkpoint"
LOG_FILE="$HOME/.rpi_setup.log"
LOCK_FILE="/tmp/rpi_setup.lock"

############################################################
# Exit trap and cleanup
############################################################
cleanup() {
  local exit_code=$?
  sudo -k 2>/dev/null || true
  rm -f "$LOCK_FILE"
  
  if [ $exit_code -ne 0 ]; then
    echo -e "${RED}[ERROR]${NC} Script exited with error code $exit_code" >&2
    echo -e "${RED}[ERROR]${NC} Check log file: $LOG_FILE" >&2
  fi
  
  exit $exit_code
}
trap cleanup EXIT INT TERM

############################################################
# Colors and logging functions
############################################################
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()     { echo -e "${BLUE}[INFO $(date +%H:%M:%S)]${NC} $1"; }
log_success()  { echo -e "${GREEN}[SUCCESS $(date +%H:%M:%S)]${NC} $1"; }
log_warning()  { echo -e "${YELLOW}[WARNING $(date +%H:%M:%S)]${NC} $1"; }
log_error()    { echo -e "${RED}[ERROR $(date +%H:%M:%S)]${NC} $1" >&2; }
log_progress() { echo -e "${CYAN}[PROGRESS $(date +%H:%M:%S)]${NC} $1"; }
log_temp()     { echo -e "${MAGENTA}[TEMP $(date +%H:%M:%S)]${NC} $1"; }
log_debug()    { [ "${DEBUG:-0}" -eq 1 ] && echo -e "[DEBUG $(date +%H:%M:%S)] $1" || true; }

############################################################
# Logging setup
############################################################
setup_logging() {
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE")
  exec 2>&1
  log_info "=== Script started at $(date) ==="
  log_info "Version: $SCRIPT_VERSION"
}

############################################################
# Lock mechanism
############################################################
acquire_lock() {
  local max_wait=300
  local waited=0
  
  while [ -e "$LOCK_FILE" ]; do
    if [ $waited -ge $max_wait ]; then
      log_error "Could not acquire lock after ${max_wait}s"
      log_error "If no other instance is running, remove: $LOCK_FILE"
      exit 1
    fi
    log_warning "Lock file exists. Waiting..."
    sleep 5
    waited=$((waited + 5))
  done
  
  echo $$ > "$LOCK_FILE"
  chmod 600 "$LOCK_FILE"
}

############################################################
# Self-heal CRLF
############################################################
fix_and_reexec() {
  local tmp
  tmp="$(mktemp)"
  tr -d '\r' < "$1" > "$tmp"
  chmod +x "$tmp"
  log_info "CRLF detected, converting and re-executing..."
  exec /bin/bash "$tmp" "$@"
}

if [ -n "${BASH_SOURCE[0]:-}" ] && [ -r "${BASH_SOURCE[0]}" ]; then
  if grep -q $'\r' "${BASH_SOURCE[0]}" 2>/dev/null; then
    fix_and_reexec "${BASH_SOURCE[0]}" "$@"
  fi
fi

############################################################
# Input validation functions
############################################################
validate_number() {
  local value="$1"
  local min="${2:-0}"
  local max="${3:-999999}"
  
  [[ "$value" =~ ^[0-9]+$ ]] || return 1
  [ "$value" -ge "$min" ] && [ "$value" -le "$max" ]
}

validate_hostname() {
  local hostname="$1"
  [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] && [ ${#hostname} -le 63 ]
}

validate_ip() {
  local ip="$1"
  [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  
  local IFS='.'
  local -a octets=($ip)
  
  for octet in "${octets[@]}"; do
    [ "$octet" -gt 255 ] && return 1
  done
  return 0
}

validate_email() {
  local email="$1"
  [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]
}

validate_cidr() {
  local cidr="$1"
  [[ "$cidr" =~ ^([0-9.]+)/([0-9]+)$ ]] || return 1
  
  local ip="${BASH_REMATCH[1]}"
  local prefix="${BASH_REMATCH[2]}"
  
  validate_ip "$ip" || return 1
  validate_number "$prefix" 0 32
}

############################################################
# Atomic file operations
############################################################
atomic_write() {
  local target="$1"
  local content="$2"
  local mode="${3:-600}"
  local tmp
  
  tmp=$(mktemp "${target}.XXXXXX")
  echo "$content" > "$tmp"
  chmod "$mode" "$tmp"
  mv "$tmp" "$target"
}

############################################################
# Locale setup
############################################################
setup_locale() {
  log_info "Setting up locale (en_GB.UTF-8)..."
  
  export LC_ALL=C.UTF-8
  export LANG=C.UTF-8
  
  local max_retries=3
  local attempt=1
  
  while [ $attempt -le $max_retries ]; do
    if sudo apt-get update -y && sudo apt-get install -y locales; then
      break
    fi
    
    log_warning "Locale package installation failed (attempt $attempt/$max_retries)"
    
    if [ $attempt -eq $max_retries ]; then
      log_error "Failed to install locales package"
      return 1
    fi
    
    sleep 5
    attempt=$((attempt + 1))
  done
  
  if ! grep -qi '^en_GB\.UTF-8 UTF-8' /etc/locale.gen; then
    sudo sed -i 's/^# *en_GB\.UTF-8 UTF-8/en_GB.UTF-8 UTF-8/' /etc/locale.gen
    grep -q '^en_GB\.UTF-8 UTF-8' /etc/locale.gen || echo 'en_GB.UTF-8 UTF-8' | sudo tee -a /etc/locale.gen >/dev/null
  fi
  
  if ! sudo locale-gen en_GB.UTF-8; then
    log_error "Failed to generate locale"
    return 1
  fi
  
  sudo sed -i '/^LC_ALL=/d' /etc/default/locale
  sudo update-locale LANG=en_GB.UTF-8 LANGUAGE="en_GB:en"
  
  export LANG=en_GB.UTF-8
  unset LC_ALL
  
  log_success "Locale configured successfully"
}

############################################################
# TTY detection and user interaction
############################################################
IS_TTY=0
{ [ -t 0 ] || [ -t 1 ] || [ -t 2 ] || [ -r /dev/tty ]; } && IS_TTY=1

NON_INTERACTIVE=0
PRESET_TIER=""
PRESET_PROFILE=""
FORCE_RERUN=0
DEBUG=0
DRY_RUN=0
ENABLE_VNC=0

while [[ $# -gt 0 ]]; do
  case $1 in
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --tier) PRESET_TIER="$2"; shift 2 ;;
    --profile) PRESET_PROFILE="$2"; shift 2 ;;
    --force) FORCE_RERUN=1; shift ;;
    --debug) DEBUG=1; shift ;;
    --dry-run) DRY_RUN=1; NON_INTERACTIVE=1; shift ;;
    --enable-vnc) ENABLE_VNC=1; shift ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --non-interactive       Run without prompts"
      echo "  --tier TIER            MINIMAL/LOW/MEDIUM/HIGH"
      echo "  --profile PROFILE      generic/web/iot/media/dev"
      echo "  --force                Force rerun"
      echo "  --debug                Enable debug logging"
      echo "  --dry-run              Preview changes only"
      echo "  --enable-vnc           Enable VNC server"
      echo "  --help                 Show this help"
      exit 0
      ;;
    *) log_error "Unknown option: $1"; exit 1 ;;
  esac
done

prompt_yn() {
  local question="$1" default="${2:-n}" ans
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would prompt: '$question' (defaulting to $default)"
    ans="$default"
  elif [ "$NON_INTERACTIVE" -eq 1 ]; then
    log_debug "Non-interactive: defaulting '$question' to $default"
    ans="$default"
  elif [ "$IS_TTY" -eq 1 ]; then
    if [ -r /dev/tty ]; then
      read -r -p "$question" ans < /dev/tty || ans="$default"
    else
      read -r -p "$question" ans || ans="$default"
    fi
  else
    log_debug "Non-interactive: defaulting '$question' to $default"
    ans="$default"
  fi
  
  [[ "$ans" =~ ^[Yy]$ ]]
}

read_tty() {
  local prompt="$1" var default="${2:-}"
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would prompt: '$prompt'"
    echo "$default"
    return
  fi
  
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    echo "$default"
  elif [ "$IS_TTY" -eq 1 ]; then
    if [ -r /dev/tty ]; then
      read -r -p "$prompt" var < /dev/tty || var="$default"
    else
      read -r -p "$prompt" var || var="$default"
    fi
    echo "${var:-$default}"
  else
    echo "$default"
  fi
}

read_secure() {
  local prompt="$1" var
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would prompt for secure input"
    echo "dummy_password"
    return
  fi
  
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    log_error "Cannot read secure input in non-interactive mode"
    return 1
  fi
  
  if [ "$IS_TTY" -eq 1 ]; then
    if [ -r /dev/tty ]; then
      read -rs -p "$prompt" var < /dev/tty || var=""
    else
      read -rs -p "$prompt" var || var=""
    fi
    echo "" >&2
    echo "$var"
  else
    log_error "Cannot read secure input without TTY"
    return 1
  fi
}

if [ "$EUID" -eq 0 ]; then
  log_error "Do not run as root. Script will prompt for sudo when needed"
  exit 1
fi

############################################################
# Temperature monitoring
############################################################
check_temperature() {
  command -v vcgencmd &>/dev/null || return 0
  
  local temp_str temp temp_int
  temp_str=$(vcgencmd measure_temp 2>&1) || return 0
  temp=$(echo "$temp_str" | grep -oP '\d+\.\d+' | head -1)
  [ -z "$temp" ] && return 0
  
  temp_int=$(echo "$temp" | cut -d. -f1)
  validate_number "$temp_int" 0 150 || return 0
  
  log_temp "CPU Temperature: ${temp}°C"
  
  if [ "$temp_int" -gt 80 ]; then
    log_temp "CRITICAL temperature! Pausing for cooldown..."
    sleep 30
    return 1
  elif [ "$temp_int" -gt 70 ]; then
    log_temp "High temperature, slowing down..."
    sleep 10
  fi
  
  return 0
}

############################################################
# Checkpointing system
############################################################
save_checkpoint() {
  atomic_write "$CHECKPOINT_FILE" "$1" 600
  log_progress "Checkpoint saved: $1"
}

load_checkpoint() {
  [ -f "$CHECKPOINT_FILE" ] && cat "$CHECKPOINT_FILE" || echo "START"
}

clear_checkpoint() {
  rm -f "$CHECKPOINT_FILE"
  log_debug "Checkpoint cleared"
}

is_checkpoint_passed() {
  local checkpoint="$1"
  local current
  current=$(load_checkpoint)
  
  local -a checkpoints=(
    START LOCALE DETECT HOSTNAME NETWORK SWAP
    UPDATE UPGRADE ESSENTIAL SECURITY VNC GIT
    EMAIL RASPI_CONFIG PYTHON PROFILE ALIASES COMPLETE
  )
  
  [ "$current" = "COMPLETE" ] && return 0
  
  local current_idx=-1
  local check_idx=-1
  
  for i in "${!checkpoints[@]}"; do
    [ "${checkpoints[$i]}" = "$current" ] && current_idx=$i
    [ "${checkpoints[$i]}" = "$checkpoint" ] && check_idx=$i
  done
  
  [ $check_idx -eq -1 ] && return 1
  [ $current_idx -eq -1 ] && return 1
  [ $current_idx -le $check_idx ] && return 1
  
  return 0
}

############################################################
# State management
############################################################
save_state() {
  local state_content
  state_content=$(cat <<EOF
PI_MODEL=${PI_MODEL:-unknown}
PI_MEMORY=${PI_MEMORY:-0}
PI_ARCH=${PI_ARCH:-unknown}
PERF_TIER=${PERF_TIER:-MEDIUM}
PROFILE=${PROFILE:-generic}
HOSTNAME=${NEW_HOSTNAME:-$(hostname)}
SERIAL=${PI_SERIAL:-UNKNOWN}
INSTALL_DATE=$(date +%Y-%m-%d)
SCRIPT_VERSION=$SCRIPT_VERSION
VNC_ENABLED=${VNC_ENABLED:-0}
EOF
)
  
  atomic_write "$STATE_FILE" "$state_content" 600
  log_debug "State saved"
}

load_state() {
  if [ -f "$STATE_FILE" ]; then
    if grep -q '^[A-Z_]*=' "$STATE_FILE"; then
      source "$STATE_FILE"
      return 0
    fi
  fi
  return 1
}

############################################################
# Detect Pi info
############################################################
detect_pi_info() {
  log_info "Detecting hardware..."
  
  PI_MODEL="unknown"
  PI_MEMORY=0
  PI_ARCH=$(uname -m)
  PI_SERIAL="UNKNOWN"
  
  if [ -f /proc/cpuinfo ]; then
    PI_SERIAL=$(grep -m1 Serial /proc/cpuinfo | awk '{print $3}' | tail -c 9)
    [ -z "$PI_SERIAL" ] && PI_SERIAL="UNKNOWN"
  fi
  
  if [ -f /proc/device-tree/model ]; then
    local model_string
    model_string=$(tr -d '\0' </proc/device-tree/model 2>/dev/null || echo "")
    
    case "$model_string" in
      *"Pi Zero"*|*"Pi 0"*) PI_MODEL="0" ;;
      *"Pi 5"*) PI_MODEL="5" ;;
      *"Pi 4"*) PI_MODEL="4" ;;
      *"Pi 3"*) PI_MODEL="3" ;;
      *"Pi 2"*) PI_MODEL="2" ;;
      *"Pi 1"*|*"Model B Rev"*) PI_MODEL="1" ;;
      *"Compute Module 4"*) PI_MODEL="CM4" ;;
      *"Compute Module 3"*) PI_MODEL="CM3" ;;
      *"Compute Module"*) PI_MODEL="CM" ;;
    esac
  fi
  
  if [ -f /proc/meminfo ]; then
    local mem_kb
    mem_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    if validate_number "$mem_kb"; then
      PI_MEMORY=$((mem_kb / 1024))
    fi
  fi
  
  log_info "Detected: Pi $PI_MODEL, ${PI_MEMORY}MB RAM, $PI_ARCH, Serial: $PI_SERIAL"
}

############################################################
# Performance tier
############################################################
set_performance_tier() {
  if [[ "$PI_MODEL" == "5" || "$PI_MODEL" == "4" ]]; then
    PERF_TIER="HIGH"
  elif [[ "$PI_MODEL" == "3" || "$PI_MODEL" == "CM4" || "$PI_MODEL" == "2" ]]; then
    PERF_TIER="MEDIUM"
  elif [ "$PI_MEMORY" -le 256 ]; then
    PERF_TIER="MINIMAL"
  elif [ "$PI_MEMORY" -le 512 ]; then
    PERF_TIER="LOW"
  else
    PERF_TIER="MEDIUM"
  fi
  
  log_info "Performance tier: $PERF_TIER"
}

############################################################
# Profile management
############################################################
PROFILE="generic"
PROFILE_ABBREV="GEN"

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
    case "$PRESET_TIER" in
      MINIMAL|LOW|MEDIUM|HIGH)
        PERF_TIER="$PRESET_TIER"
        log_info "Using preset tier: $PERF_TIER"
        return
        ;;
      *)
        log_error "Invalid preset tier: $PRESET_TIER"
        exit 1
        ;;
    esac
  fi
  
  echo ""
  echo "=========================================="
  echo "Select Your Raspberry Pi Model"
  echo "=========================================="
  echo "Auto-detected: Pi $PI_MODEL with ${PI_MEMORY}MB RAM"
  echo ""
  echo "1) Pi Zero/Zero W"
  echo "2) Pi 1"
  echo "3) Pi 2"
  echo "4) Pi 3"
  echo "5) Pi 4"
  echo "6) Pi 5"
  echo "7) Use auto-detected values"
  echo ""
  
  local choice
  choice=$(read_tty "Enter choice [1-7] (default: 7): " "7")
  
  case $choice in
    1) PI_MODEL="0"; PI_MEMORY=512; PI_ARCH="armv6l" ;;
    2) PI_MODEL="1"; PI_MEMORY=512; PI_ARCH="armv6l" ;;
    3) PI_MODEL="2"; PI_MEMORY=1024; PI_ARCH="armv7l" ;;
    4) PI_MODEL="3"; PI_MEMORY=1024; PI_ARCH="armv8" ;;
    5) PI_MODEL="4"; PI_MEMORY=2048; PI_ARCH="armv8" ;;
    6) PI_MODEL="5"; PI_MEMORY=8192; PI_ARCH="armv8" ;;
    7) log_info "Using auto-detected values" ;;
    *) log_warning "Invalid choice, using auto-detected values" ;;
  esac
  
  set_performance_tier
  
  echo ""
  log_info "Configuration: Pi $PI_MODEL, ${PI_MEMORY}MB RAM, $PI_ARCH"
  log_info "Performance tier: $PERF_TIER"
  echo ""
}

select_profile() {
  if [ -n "$PRESET_PROFILE" ]; then
    case "$PRESET_PROFILE" in
      generic|web|iot|media|dev)
        PROFILE="$PRESET_PROFILE"
        set_profile_abbrev
        log_info "Using preset profile: $PROFILE"
        return
        ;;
      *)
        log_error "Invalid preset profile: $PRESET_PROFILE"
        exit 1
        ;;
    esac
  fi
  
  echo ""
  echo "=========================================="
  echo "Select Installation Profile"
  echo "=========================================="
  echo "1) Generic (GEN)"
  echo "2) Web Server (WEB)"
  echo "3) IoT Sensor (IOT)"
  echo "4) Media Center (MED)"
  echo "5) Development (DEV)"
  echo ""
  
  local choice
  choice=$(read_tty "Enter choice [1-5] (default: 1): " "1")
  
  case $choice in
    1) PROFILE="generic" ;;
    2) PROFILE="web" ;;
    3) PROFILE="iot" ;;
    4) PROFILE="media" ;;
    5) PROFILE="dev" ;;
    *) PROFILE="generic" ;;
  esac
  
  set_profile_abbrev
  log_info "Selected profile: $PROFILE"
}

############################################################
# Hostname configuration
############################################################
set_hostname() {
  NEW_HOSTNAME="LH-PI${PI_MODEL}-${PI_SERIAL}-${PROFILE_ABBREV}"
  CURRENT_HOSTNAME=$(hostname)
  
  log_info "Current hostname: $CURRENT_HOSTNAME"
  log_info "Proposed hostname: $NEW_HOSTNAME"
  
  if ! validate_hostname "$NEW_HOSTNAME"; then
    log_warning "Generated hostname invalid, using fallback"
    NEW_HOSTNAME="rpi-${PI_SERIAL}"
    
    if ! validate_hostname "$NEW_HOSTNAME"; then
      NEW_HOSTNAME="$CURRENT_HOSTNAME"
      return
    fi
  fi
  
  if [ "$CURRENT_HOSTNAME" = "$NEW_HOSTNAME" ]; then
    log_info "Hostname already correct"
    return
  fi
  
  if prompt_yn "Set hostname to $NEW_HOSTNAME? (y/n): " y; then
    if [ "$DRY_RUN" -eq 0 ]; then
      echo "$NEW_HOSTNAME" | sudo tee /etc/hostname >/dev/null
      sudo sed -i "s/127.0.1.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
      sudo hostnamectl set-hostname "$NEW_HOSTNAME" 2>/dev/null || true
      log_success "Hostname set to $NEW_HOSTNAME"
    fi
  else
    NEW_HOSTNAME="$CURRENT_HOSTNAME"
  fi
}

############################################################
# Network helpers
############################################################
configure_network() {
  log_info "Network configuration..."
  
  if ! prompt_yn "Set static IPv4 address? (y/n): " n; then
    log_info "Keeping DHCP"
    return
  fi
  
  log_info "Static IP configuration available but simplified for this version"
  log_info "To configure manually: sudo nano /etc/dhcpcd.conf"
}

############################################################
# Swap setup
############################################################
setup_swap() {
  [ "$PI_MEMORY" -gt 512 ] && return
  
  log_info "Low memory detected. Checking swap..."
  
  local current_swap
  current_swap=$(free -m | awk '/^Swap:/ {print $2}')
  
  [ "$current_swap" -ge 1024 ] && return
  
  if prompt_yn "Increase swap to 1024MB? (y/n): " y; then
    if [ "$DRY_RUN" -eq 0 ]; then
      sudo dphys-swapfile swapoff 2>/dev/null || true
      
      if [ -f /etc/dphys-swapfile ]; then
        sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile
      else
        echo "CONF_SWAPSIZE=1024" | sudo tee /etc/dphys-swapfile >/dev/null
      fi
      
      sudo dphys-swapfile setup && sudo dphys-swapfile swapon
      log_success "Swap increased to 1024MB"
    fi
  fi
}

############################################################
# Piwheels
############################################################
setup_piwheels() {
  log_info "Configuring piwheels..."
  
  [ "$DRY_RUN" -eq 1 ] && return
  
  mkdir -p ~/.pip
  
  [ -f ~/.pip/pip.conf ] && grep -q "piwheels" ~/.pip/pip.conf && return
  
  cat > ~/.pip/pip.conf <<'EOF'
[global]
extra-index-url=https://www.piwheels.org/simple
EOF
  
  chmod 600 ~/.pip/pip.conf
  log_success "Piwheels configured"
}

############################################################
# Progress indicator
############################################################
show_progress() {
  local pid=$1
  local message=$2
  local elapsed=0
  
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${CYAN}[PROGRESS]${NC} %s... %d seconds" "$message" "$elapsed"
    sleep 5
    elapsed=$((elapsed + 5))
    check_temperature || sleep 20
  done
  
  wait "$pid"
  local exit_code=$?
  
  printf "\r${CYAN}[PROGRESS]${NC} %s... Complete! (%d seconds)          \n" "$message" "$elapsed"
  
  return $exit_code
}

############################################################
# VNC Setup
############################################################
setup_vnc() {
  log_info "Setting up VNC server..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would install and configure VNC"
    return
  fi
  
  if ! command -v vncserver >/dev/null 2>&1; then
    log_info "Installing VNC server..."
    if ! sudo apt-get install -y realvnc-vnc-server 2>/dev/null; then
      log_warning "RealVNC failed, trying TigerVNC..."
      sudo apt-get install -y tigervnc-standalone-server tigervnc-common || log_error "VNC install failed"
    fi
  fi
  
  if command -v raspi-config >/dev/null 2>&1; then
    sudo raspi-config nonint do_vnc 0 || true
  fi
  
  if systemctl list-unit-files | grep -q vncserver-x11-serviced; then
    sudo systemctl enable vncserver-x11-serviced.service || true
    sudo systemctl start vncserver-x11-serviced.service || true
  fi
  
  log_info "Configuring firewall for VNC (port 5900)..."
  sudo ufw allow 5900/tcp comment 'VNC Server' && log_success "VNC firewall rule added"
  
  sleep 2
  if ss -tln 2>/dev/null | grep -q ':5900'; then
    log_success "VNC server running on port 5900"
    local ip_addr
    ip_addr=$(hostname -I | awk '{print $1}')
    log_info "Connect to: ${ip_addr}:5900"
  else
    log_warning "VNC may not be running yet. Try rebooting."
  fi
  
  VNC_ENABLED=1
}

############################################################
# Package installation
############################################################
install_packages() {
  local package_list=("$@")
  [ ${#package_list[@]} -eq 0 ] && return 0
  
  log_info "Installing: ${package_list[*]}"
  [ "$DRY_RUN" -eq 1 ] && return 0
  
  local max_retries=3
  local attempt=1
  
  while [ $attempt -le $max_retries ]; do
    if sudo apt-get install -y "${package_list[@]}"; then
      log_success "Packages installed"
      return 0
    fi
    
    log_warning "Install failed (attempt $attempt/$max_retries)"
    
    if [ $attempt -eq $max_retries ]; then
      log_error "Failed after $max_retries attempts"
      return 1
    fi
    
    sleep 5
    sudo apt-get --fix-broken install -y || true
    sudo apt-get update -y || true
    
    attempt=$((attempt + 1))
  done
  
  return 1
}

############################################################
# Initialize
############################################################
setup_logging
acquire_lock

clear
cat << "EOF"
╔════════════════════════════════════════╗
║  Universal Raspberry Pi Setup Script  ║
║     Enhanced Security Edition          ║
╚════════════════════════════════════════╝
EOF
echo ""
log_info "Version: $SCRIPT_VERSION"
echo ""

[ "$DRY_RUN" -eq 1 ] && log_warning "DRY-RUN MODE: No changes will be made"

############################################################
# Recovery / Resume
############################################################
LAST
