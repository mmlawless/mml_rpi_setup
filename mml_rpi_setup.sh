#!/bin/bash
set -euo pipefail

############################################################
# Universal Raspberry Pi Setup Script
# Version: 2024-10-20-Secure
# Features: Enhanced security, validation, VNC support,
#           proper error handling, and comprehensive logging
############################################################

SCRIPT_VERSION="2024-10-20-Secure"
SCRIPT_HASH="PLACEHOLDER_HASH"  # Replace with actual SHA256 after script finalization

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
  sudo -k 2>/dev/null || true  # Clear sudo cache
  rm -f "$LOCK_FILE"
  
  if [ $exit_code -ne 0 ]; then
    log_error "Script exited with error code $exit_code"
    log_error "Check log file: $LOG_FILE"
  fi
  
  exit $exit_code
}
trap cleanup EXIT INT TERM

############################################################
# Logging setup (both file and console)
############################################################
setup_logging() {
  # Ensure log file exists with correct permissions
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE"
  
  # Log to both file and console
  exec > >(tee -a "$LOG_FILE")
  exec 2>&1
  
  log_info "=== Script started at $(date) ==="
  log_info "Version: $SCRIPT_VERSION"
}

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
# Lock mechanism to prevent concurrent runs
############################################################
acquire_lock() {
  local max_wait=300  # 5 minutes
  local waited=0
  
  while [ -e "$LOCK_FILE" ]; do
    if [ $waited -ge $max_wait ]; then
      log_error "Could not acquire lock after ${max_wait}s. Another instance may be running."
      log_error "If you're sure no other instance is running, remove: $LOCK_FILE"
      exit 1
    fi
    
    log_warning "Lock file exists. Waiting for other instance to complete..."
    sleep 5
    waited=$((waited + 5))
  done
  
  echo $$ > "$LOCK_FILE"
  chmod 600 "$LOCK_FILE"
}

############################################################
# Self-heal CRLF and support curl | bash execution
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
# Script integrity verification
############################################################
verify_script_integrity() {
  # Skip verification if hash is placeholder or we're piped from curl
  if [ "$SCRIPT_HASH" = "PLACEHOLDER_HASH" ]; then
    log_warning "Script integrity check skipped (placeholder hash)"
    return 0
  fi
  
  if [ ! -r "${BASH_SOURCE[0]}" ]; then
    log_warning "Script integrity check skipped (piped execution)"
    return 0
  fi
  
  local actual_hash
  if command -v sha256sum >/dev/null 2>&1; then
    actual_hash=$(sha256sum "${BASH_SOURCE[0]}" | cut -d' ' -f1)
  elif command -v shasum >/dev/null 2>&1; then
    actual_hash=$(shasum -a 256 "${BASH_SOURCE[0]}" | cut -d' ' -f1)
  else
    log_warning "No SHA256 tool available, skipping integrity check"
    return 0
  fi
  
  if [ "$actual_hash" != "$SCRIPT_HASH" ]; then
    log_error "Script integrity check FAILED!"
    log_error "Expected: $SCRIPT_HASH"
    log_error "Got:      $actual_hash"
    log_error "Script may have been tampered with. Aborting."
    exit 1
  fi
  
  log_success "Script integrity verified"
}

############################################################
# Input validation functions
############################################################
validate_number() {
  local value="$1"
  local min="${2:-0}"
  local max="${3:-999999}"
  
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  
  if [ "$value" -lt "$min" ] || [ "$value" -gt "$max" ]; then
    return 1
  fi
  
  return 0
}

validate_hostname() {
  local hostname="$1"
  
  # RFC 1123 hostname validation
  if [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]]; then
    return 1
  fi
  
  if [ ${#hostname} -gt 63 ]; then
    return 1
  fi
  
  return 0
}

validate_ip() {
  local ip="$1"
  
  # Basic IPv4 validation
  if [[ ! "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    return 1
  fi
  
  local IFS='.'
  local -a octets=($ip)
  
  for octet in "${octets[@]}"; do
    if [ "$octet" -gt 255 ]; then
      return 1
    fi
  done
  
  return 0
}

validate_email() {
  local email="$1"
  
  # Basic email validation
  if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    return 1
  fi
  
  return 0
}

validate_cidr() {
  local cidr="$1"
  local ip prefix
  
  if [[ ! "$cidr" =~ ^([0-9.]+)/([0-9]+)$ ]]; then
    return 1
  fi
  
  ip="${BASH_REMATCH[1]}"
  prefix="${BASH_REMATCH[2]}"
  
  validate_ip "$ip" || return 1
  
  if ! validate_number "$prefix" 0 32; then
    return 1
  fi
  
  return 0
}

############################################################
# Secure file operations with atomic writes
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

secure_sudo_write() {
  local target="$1"
  local mode="${2:-644}"
  local tmp
  
  tmp=$(sudo mktemp "${target}.XXXXXX")
  cat | sudo tee "$tmp" >/dev/null
  sudo chmod "$mode" "$tmp"
  sudo mv "$tmp" "$target"
}

############################################################
# Locale setup (defensive; do NOT persist LC_ALL)
############################################################
setup_locale() {
  log_info "Setting up locale (en_GB.UTF-8)..."
  
  # Use safe temporary locale
  export LC_ALL=C.UTF-8
  export LANG=C.UTF-8
  
  # Install locales package with retry
  local max_retries=3
  local attempt=1
  
  while [ $attempt -le $max_retries ]; do
    if sudo apt-get update -y && sudo apt-get install -y locales; then
      break
    fi
    
    log_warning "Locale package installation failed (attempt $attempt/$max_retries)"
    
    if [ $attempt -eq $max_retries ]; then
      log_error "Failed to install locales package after $max_retries attempts"
      return 1
    fi
    
    sleep 5
    attempt=$((attempt + 1))
  done
  
  # Ensure en_GB.UTF-8 is enabled
  if ! grep -qi '^en_GB\.UTF-8 UTF-8' /etc/locale.gen; then
    sudo sed -i 's/^# *en_GB\.UTF-8 UTF-8/en_GB.UTF-8 UTF-8/' /etc/locale.gen
    grep -q '^en_GB\.UTF-8 UTF-8' /etc/locale.gen || echo 'en_GB.UTF-8 UTF-8' | sudo tee -a /etc/locale.gen >/dev/null
  fi
  
  # Generate locale with error handling
  if ! sudo locale-gen en_GB.UTF-8; then
    log_error "Failed to generate locale"
    return 1
  fi
  
  # Update system locale (no LC_ALL in /etc/default/locale)
  sudo sed -i '/^LC_ALL=/d' /etc/default/locale
  sudo update-locale LANG=en_GB.UTF-8 LANGUAGE="en_GB:en"
  
  # Switch this shell to final locale
  export LANG=en_GB.UTF-8
  unset LC_ALL
  
  log_success "Locale configured successfully"
}

############################################################
# TTY detection and user interaction
############################################################
IS_TTY=0
{ [ -t 0 ] || [ -t 1 ] || [ -t 2 ] || [ -r /dev/tty ]; } && IS_TTY=1

# Command line arguments
NON_INTERACTIVE=0
PRESET_TIER=""
PRESET_PROFILE=""
FORCE_RERUN=0
DEBUG=0
DRY_RUN=0
ENABLE_VNC=0

# Parse command line arguments
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
      echo "  --non-interactive       Run without prompts (use defaults)"
      echo "  --tier TIER            MINIMAL/LOW/MEDIUM/HIGH"
      echo "  --profile PROFILE      generic/web/iot/media/dev"
      echo "  --force                Force rerun from scratch"
      echo "  --debug                Enable debug logging"
      echo "  --dry-run              Show what would be done (implies --non-interactive)"
      echo "  --enable-vnc           Enable VNC server and configure firewall"
      echo "  --help                 Show this help"
      echo ""
      echo "Examples:"
      echo "  $0 --tier HIGH --profile dev --enable-vnc"
      echo "  $0 --non-interactive --tier MEDIUM --profile web"
      echo "  curl -fsSL <script-url> | bash -s -- --non-interactive --enable-vnc"
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
    log_debug "Non-interactive mode: defaulting '$question' to $default"
    ans="$default"
  elif [ "$IS_TTY" -eq 1 ]; then
    if [ -r /dev/tty ]; then
      read -r -p "$question" ans < /dev/tty || ans="$default"
    else
      read -r -p "$question" ans || ans="$default"
    fi
  else
    log_debug "Non-interactive mode: defaulting '$question' to $default"
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
    log_info "[DRY-RUN] Would prompt for secure input: '$prompt'"
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
    echo "" >&2  # Newline after hidden input
    echo "$var"
  else
    log_error "Cannot read secure input without TTY"
    return 1
  fi
}

############################################################
# Root check
############################################################
if [ "$EUID" -eq 0 ]; then
  log_error "Please do not run this script as root or with sudo"
  log_error "The script will prompt for sudo when needed"
  exit 1
fi

############################################################
# Temperature monitoring with proper error handling
############################################################
check_temperature() {
  if ! command -v vcgencmd &>/dev/null; then
    log_debug "vcgencmd not available, skipping temperature check"
    return 0
  fi
  
  local temp_str temp temp_int
  
  if ! temp_str=$(vcgencmd measure_temp 2>&1); then
    log_debug "Failed to read temperature: $temp_str"
    return 0
  fi
  
  temp=$(echo "$temp_str" | grep -oP '\d+\.\d+' | head -1)
  
  if [ -z "$temp" ]; then
    log_debug "Could not parse temperature from: $temp_str"
    return 0
  fi
  
  temp_int=$(echo "$temp" | cut -d. -f1)
  
  if ! validate_number "$temp_int" 0 150; then
    log_warning "Invalid temperature reading: ${temp}°C"
    return 0
  fi
  
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
# Checkpointing system with atomic operations
############################################################
save_checkpoint() {
  local checkpoint="$1"
  atomic_write "$CHECKPOINT_FILE" "$checkpoint" 600
  log_progress "Checkpoint saved: $checkpoint"
}

load_checkpoint() {
  if [ -f "$CHECKPOINT_FILE" ]; then
    cat "$CHECKPOINT_FILE"
  else
    echo "START"
  fi
}

clear_checkpoint() {
  rm -f "$CHECKPOINT_FILE"
  log_debug "Checkpoint cleared"
}

is_checkpoint_passed() {
  local checkpoint="$1"
  local current
  current=$(load_checkpoint)
  
  # Define checkpoint order
  local -a checkpoints=(
    START LOCALE DETECT HOSTNAME NETWORK SWAP
    UPDATE UPGRADE ESSENTIAL SECURITY VNC GIT
    EMAIL RASPI_CONFIG PYTHON PROFILE ALIASES COMPLETE
  )
  
  # Find indices
  local current_idx=-1
  local check_idx=-1
  
  for i in "${!checkpoints[@]}"; do
    [ "${checkpoints[$i]}" = "$current" ] && current_idx=$i
    [ "${checkpoints[$i]}" = "$checkpoint" ] && check_idx=$i
  done
  
  # If we're at COMPLETE, all checkpoints are passed
  [ "$current" = "COMPLETE" ] && return 0
  
  # If checkpoint not found or we haven't reached it yet
  [ $check_idx -eq -1 ] && return 1
  [ $current_idx -eq -1 ] && return 1
  [ $current_idx -le $check_idx ] && return 1
  
  return 0
}

############################################################
# State management with validation
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
  log_debug "State saved to $STATE_FILE"
}

load_state() {
  if [ -f "$STATE_FILE" ]; then
    # Validate state file before sourcing
    if grep -q '^[A-Z_]*=' "$STATE_FILE"; then
      # shellcheck disable=SC1090
      source "$STATE_FILE"
      log_debug "State loaded from $STATE_FILE"
      return 0
    else
      log_warning "State file appears corrupted, ignoring"
      return 1
    fi
  fi
  return 1
}

############################################################
# Detect Pi info with validation
############################################################
detect_pi_info() {
  log_info "Detecting Raspberry Pi hardware..."
  
  PI_MODEL="unknown"
  PI_MEMORY=0
  PI_ARCH=$(uname -m)
  PI_SERIAL="UNKNOWN"
  
  # Get serial number
  if [ -f /proc/cpuinfo ]; then
    PI_SERIAL=$(grep -m1 Serial /proc/cpuinfo | awk '{print $3}' | tail -c 9)
    [ -z "$PI_SERIAL" ] && PI_SERIAL="UNKNOWN"
  fi
  
  # Detect model
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
  
  # Detect memory
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
# Performance tier determination
############################################################
set_performance_tier() {
  if [[ "$PI_MODEL" == "5" ]]; then
    PERF_TIER="HIGH"
  elif [[ "$PI_MODEL" == "4" ]]; then
    PERF_TIER="HIGH"
  elif [[ "$PI_MODEL" == "3" ]] || [[ "$PI_MODEL" == "CM4" ]]; then
    PERF_TIER="MEDIUM"
  elif [[ "$PI_MODEL" == "2" ]]; then
    PERF_TIER="MEDIUM"
  elif [ "$PI_MEMORY" -le 256 ]; then
    PERF_TIER="MINIMAL"
  elif [ "$PI_MEMORY" -le 512 ]; then
    PERF_TIER="LOW"
  else
    PERF_TIER="MEDIUM"
  fi
  
  log_info "Performance tier set to: $PERF_TIER"
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
    # Validate preset tier
    case "$PRESET_TIER" in
      MINIMAL|LOW|MEDIUM|HIGH)
        PERF_TIER="$PRESET_TIER"
        log_info "Using preset tier: $PERF_TIER"
        return
        ;;
      *)
        log_error "Invalid preset tier: $PRESET_TIER"
        log_error "Valid options: MINIMAL, LOW, MEDIUM, HIGH"
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
  echo "8) Manual override"
  echo ""
  
  local choice
  choice=$(read_tty "Enter choice [1-8] (default: 7): " "7")
  
  case $choice in
    1)
      PI_MODEL="0"
      PI_MEMORY=512
      PI_ARCH="armv6l"
      ;;
    2)
      PI_MODEL="1"
      local mem
      mem=$(read_tty "Memory [256/512] (default: 512): " "512")
      if validate_number "$mem" 256 512; then
        PI_MEMORY=$mem
      else
        log_warning "Invalid memory, using 512MB"
        PI_MEMORY=512
      fi
      PI_ARCH="armv6l"
      ;;
    3)
      PI_MODEL="2"
      PI_MEMORY=1024
      PI_ARCH="armv7l"
      ;;
    4)
      PI_MODEL="3"
      PI_MEMORY=1024
      PI_ARCH="armv8"
      ;;
    5)
      PI_MODEL="4"
      local mem_choice
      mem_choice=$(read_tty "RAM [1024/2048/4096/8192] (default: 2048): " "2048")
      if validate_number "$mem_choice" 1024 8192; then
        PI_MEMORY=$mem_choice
      else
        log_warning "Invalid memory, using 2048MB"
        PI_MEMORY=2048
      fi
      PI_ARCH="armv8"
      ;;
    6)
      PI_MODEL="5"
      local mem_choice
      mem_choice=$(read_tty "RAM [4096/8192] (default: 8192): " "8192")
      if validate_number "$mem_choice" 4096 8192; then
        PI_MEMORY=$mem_choice
      else
        log_warning "Invalid memory, using 8192MB"
        PI_MEMORY=8192
      fi
      PI_ARCH="armv8"
      ;;
    7)
      log_info "Using auto-detected values"
      ;;
    8)
      local model mem arch
      model=$(read_tty "Enter Pi model (0/1/2/3/4/5): " "$PI_MODEL")
      mem=$(read_tty "Enter RAM in MB: " "$PI_MEMORY")
      arch=$(read_tty "Enter architecture (armv6l/armv7l/armv8/aarch64): " "$PI_ARCH")
      
      if validate_number "$mem" 128 16384; then
        PI_MEMORY=$mem
      else
        log_warning "Invalid memory value, keeping auto-detected"
      fi
      
      case "$arch" in
        armv6l|armv7l|armv8|aarch64)
          PI_ARCH=$arch
          ;;
        *)
          log_warning "Invalid architecture, keeping auto-detected"
          ;;
      esac
      
      PI_MODEL=$model
      ;;
    *)
      log_warning "Invalid choice, using auto-detected values"
      ;;
  esac
  
  set_performance_tier
  
  echo ""
  log_info "Configuration: Pi $PI_MODEL, ${PI_MEMORY}MB RAM, $PI_ARCH"
  log_info "Performance tier: $PERF_TIER"
  log_info "Serial: $PI_SERIAL"
  echo ""
}

select_profile() {
  if [ -n "$PRESET_PROFILE" ]; then
    # Validate preset profile
    case "$PRESET_PROFILE" in
      generic|web|iot|media|dev)
        PROFILE="$PRESET_PROFILE"
        set_profile_abbrev
        log_info "Using preset profile: $PROFILE ($PROFILE_ABBREV)"
        return
        ;;
      *)
        log_error "Invalid preset profile: $PRESET_PROFILE"
        log_error "Valid options: generic, web, iot, media, dev"
        exit 1
        ;;
    esac
  fi
  
  echo ""
  echo "=========================================="
  echo "Select Installation Profile"
  echo "=========================================="
  echo "1) Generic (GEN)         - Basic setup"
  echo "2) Web Server (WEB)      - Nginx, PHP, Database"
  echo "3) IoT Sensor (IOT)      - MQTT, sensors, GPIO"
  echo "4) Media Center (MED)    - VLC, media tools"
  echo "5) Development (DEV)     - Docker, dev tools"
  echo ""
  
  local choice
  choice=$(read_tty "Enter choice [1-5] (default: 1): " "1")
  
  case $choice in
    1) PROFILE="generic" ;;
    2) PROFILE="web" ;;
    3) PROFILE="iot" ;;
    4) PROFILE="media" ;;
    5) PROFILE="dev" ;;
    *)
      log_warning "Invalid choice, using generic profile"
      PROFILE="generic"
      ;;
  esac
  
  set_profile_abbrev
  log_info "Selected profile: $PROFILE ($PROFILE_ABBREV)"
}

############################################################
# Hostname configuration with validation
############################################################
set_hostname() {
  NEW_HOSTNAME="LH-PI${PI_MODEL}-${PI_SERIAL}-${PROFILE_ABBREV}"
  CURRENT_HOSTNAME=$(hostname)
  
  log_info "Current hostname: $CURRENT_HOSTNAME"
  log_info "Proposed hostname: $NEW_HOSTNAME"
  
  # Validate proposed hostname
  if ! validate_hostname "$NEW_HOSTNAME"; then
    log_warning "Generated hostname is invalid, using fallback"
    NEW_HOSTNAME="rpi-${PI_SERIAL}"
    
    if ! validate_hostname "$NEW_HOSTNAME"; then
      log_warning "Fallback hostname also invalid, keeping current"
      NEW_HOSTNAME="$CURRENT_HOSTNAME"
      return
    fi
  fi
  
  if [ "$CURRENT_HOSTNAME" = "$NEW_HOSTNAME" ]; then
    log_info "Hostname already set correctly"
    return
  fi
  
  if prompt_yn "Set hostname to $NEW_HOSTNAME? (y/n): " y; then
    if [ "$DRY_RUN" -eq 1 ]; then
      log_info "[DRY-RUN] Would set hostname to $NEW_HOSTNAME"
      return
    fi
    
    echo "$NEW_HOSTNAME" | secure_sudo_write /etc/hostname 644
    sudo sed -i "s/127.0.1.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
    sudo hostnamectl set-hostname "$NEW_HOSTNAME" 2>/dev/null || true
    log_success "Hostname set to $NEW_HOSTNAME (takes effect after reboot)"
  else
    NEW_HOSTNAME="$CURRENT_HOSTNAME"
    log_info "Keeping current hostname"
  fi
}

############################################################
# Network helpers with enhanced validation
############################################################
nm_available() {
  command -v nmcli >/dev/null 2>&1 && \
  command -v systemctl >/dev/null 2>&1 && \
  systemctl is-active --quiet NetworkManager 2>/dev/null
}

get_default_iface() {
  ip route 2>/dev/null | awk '/^default/ {print $5; exit}'
}

list_ipv4_ifaces() {
  ip -o -4 addr show | awk '{print $2}' | sort -u | grep -v '^lo || true
}

iface_current_cidr() {
  local ifc="$1"
  ip -o -4 addr show dev "$ifc" 2>/dev/null | awk '{print $4}' | head -1
}

iface_current_gw() {
  ip route 2>/dev/null | awk '/^default/ {print $3; exit}'
}

is_ip_in_use() {
  local ip="$1"
  local ifc="${2:-}"
  
  log_debug "Checking if $ip is in use..."
  
  # Try ping first (quick check)
  if ping -c1 -W1 "$ip" >/dev/null 2>&1; then
    log_debug "IP $ip responded to ping"
    return 0
  fi
  
  # Try arping if available (more reliable for same subnet)
  if command -v arping >/dev/null 2>&1; then
    if [ -n "$ifc" ]; then
      if sudo arping -D -c 2 -w 2 -I "$ifc" "$ip" >/dev/null 2>&1; then
        log_debug "IP $ip found via arping on $ifc"
        return 0
      fi
    else
      if sudo arping -D -c 2 -w 2 "$ip" >/dev/null 2>&1; then
        log_debug "IP $ip found via arping"
        return 0
      fi
    fi
  fi
  
  log_debug "IP $ip appears to be free"
  return 1
}

write_dhcpcd_static() {
  local ifc="$1"
  local cidr="$2"
  local gw="$3"
  local dns="$4"
  local conf="/etc/dhcpcd.conf"
  
  log_info "Configuring static IP in dhcpcd.conf..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would configure dhcpcd with:"
    log_info "  interface: $ifc"
    log_info "  ip_address: $cidr"
    log_info "  routers: $gw"
    log_info "  dns: $dns"
    return
  fi
  
  # Use flock for atomic file modification
  (
    flock -x 200
    
    local tmp
    tmp=$(sudo mktemp /tmp/dhcpcd.conf.XXXXXX)
    
    # Remove old configuration
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
    
    # Add new configuration
    sudo bash -c "cat >> '$tmp' <<EOF
# >>> mml_rpi_setup static
interface $ifc
static ip_address=$cidr
static routers=$gw
static domain_name_servers=$dns
# <<< mml_rpi_setup static
EOF"
    
    sudo mv "$tmp" "$conf"
    sudo chmod 644 "$conf"
    
  ) 200>/var/lock/dhcpcd.lock
  
  sudo systemctl restart dhcpcd || log_warning "Failed to restart dhcpcd"
}

remove_dhcpcd_static() {
  local conf="/etc/dhcpcd.conf"
  
  log_info "Removing static IP configuration from dhcpcd.conf..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would remove static IP from dhcpcd.conf"
    return
  fi
  
  sudo test -r "$conf" || return 0
  
  (
    flock -x 200
    
    local tmp
    tmp=$(sudo mktemp /tmp/dhcpcd.conf.XXXXXX)
    
    sudo awk '
      BEGIN{skip=0}
      /# >>> mml_rpi_setup static/ {skip=1; next}
      /# <<< mml_rpi_setup static/ {skip=0; next}
      skip==0 {print}
    ' "$conf" | sudo tee "$tmp" >/dev/null
    
    sudo mv "$tmp" "$conf"
    sudo chmod 644 "$conf"
    
  ) 200>/var/lock/dhcpcd.lock
  
  sudo systemctl restart dhcpcd || log_warning "Failed to restart dhcpcd"
}

configure_static_nm() {
  local ifc="$1"
  local cidr="$2"
  local gw="$3"
  local dns="$4"
  
  log_info "Configuring static IP via NetworkManager..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would configure NetworkManager with:"
    log_info "  interface: $ifc"
    log_info "  addresses: $cidr"
    log_info "  gateway: $gw"
    log_info "  dns: $dns"
    return
  fi
  
  local conn
  conn=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | \
         awk -F: -v IF="$ifc" '$2==IF{print $1; exit}')
  
  [ -z "$conn" ] && conn="$ifc"
  
  sudo nmcli con mod "$conn" \
    ipv4.method manual \
    ipv4.addresses "$cidr" \
    ipv4.gateway "$gw" \
    ipv4.dns "$dns" \
    ipv6.method ignore
  
  sudo nmcli con up "$conn" || sudo nmcli dev reapply "$ifc" || \
    log_warning "Failed to apply NetworkManager configuration"
}

configure_dhcp_nm() {
  local ifc="$1"
  
  log_info "Configuring DHCP via NetworkManager..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would configure NetworkManager for DHCP on $ifc"
    return
  fi
  
  local conn
  conn=$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | \
         awk -F: -v IF="$ifc" '$2==IF{print $1; exit}')
  
  [ -z "$conn" ] && conn="$ifc"
  
  sudo nmcli con mod "$conn" \
    ipv4.method auto \
    ipv6.method ignore
  
  sudo nmcli con up "$conn" || sudo nmcli dev reapply "$ifc" || \
    log_warning "Failed to apply NetworkManager configuration"
}

configure_network() {
  log_info "Network configuration..."
  
  if ! prompt_yn "Would you like to set a static IPv4 address? (y/n): " n; then
    log_info "Keeping DHCP configuration"
    return
  fi
  
  local default_ifc ifaces ifc
  default_ifc="$(get_default_iface)"
  mapfile -t ifaces < <(list_ipv4_ifaces)
  
  if [ ${#ifaces[@]} -eq 0 ]; then
    log_warning "No IPv4 interface found; skipping static IP setup"
    return
  fi
  
  ifc="$default_ifc"
  
  if [ ${#ifaces[@]} -gt 1 ]; then
    echo "Available interfaces: ${ifaces[*]}"
    local sel
    sel=$(read_tty "Choose interface (default: $default_ifc): " "$default_ifc")
    ifc="${sel:-$default_ifc}"
  fi
  
  [ -z "$ifc" ] && {
    log_warning "No interface selected; skipping static IP setup"
    return
  }
  
  local current_cidr current_gw def_dns cidr_in gw_in dns_in ip_only
  current_cidr="$(iface_current_cidr "$ifc")"
  current_gw="$(iface_current_gw)"
  def_dns="1.1.1.1 8.8.8.8"
  
  # Suggest current IP with /24 if we have one
  local suggested_cidr
  if [[ "$current_cidr" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ ]]; then
    suggested_cidr="$current_cidr"
  else
    local current_ip
    current_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    suggested_cidr="${current_ip}/24"
  fi
  
  echo ""
  log_info "Enter the static IP details for interface: $ifc"
  log_info "Use CIDR notation (e.g. 192.168.1.50/24)"
  
  cidr_in=$(read_tty "Static IP (CIDR) [default: $suggested_cidr]: " "$suggested_cidr")
  
  # Validate CIDR
  if ! validate_cidr "$cidr_in"; then
    log_error "Invalid CIDR format: $cidr_in"
    log_warning "Falling back to DHCP"
    return
  fi
  
  gw_in=$(read_tty "Gateway [default: $current_gw]: " "$current_gw")
  
  # Validate gateway
  if ! validate_ip "$gw_in"; then
    log_error "Invalid gateway IP: $gw_in"
    log_warning "Falling back to DHCP"
    return
  fi
  
  dns_in=$(read_tty "DNS servers space-separated [default: $def_dns]: " "$def_dns")
  
  # Validate DNS servers
  for dns_server in $dns_in; do
    if ! validate_ip "$dns_server"; then
      log_warning "Invalid DNS server IP: $dns_server, using defaults"
      dns_in="$def_dns"
      break
    fi
  done
  
  ip_only="${cidr_in%%/*}"
  
  log_info "Checking if $ip_only is already in use on the network..."
  if is_ip_in_use "$ip_only" "$ifc"; then
    log_warning "Address $ip_only appears to be in use!"
    if ! prompt_yn "Continue anyway? (not recommended) (y/n): " n; then
      log_info "Falling back to DHCP"
      if nm_available; then
        configure_dhcp_nm "$ifc"
      else
        remove_dhcpcd_static
      fi
      return
    fi
  fi
  
  # Apply configuration
  if nm_available; then
    configure_static_nm "$ifc" "$cidr_in" "$gw_in" "$dns_in"
  else
    write_dhcpcd_static "$ifc" "$cidr_in" "$gw_in" "$dns_in"
  fi
  
  # Verify configuration
  sleep 3
  if ip -4 addr show dev "$ifc" 2>/dev/null | grep -q "$ip_only"; then
    log_success "Static IP $cidr_in set on $ifc"
  else
    log_warning "Could not verify static IP on $ifc"
    log_warning "Network may need a reboot or cable replug"
  fi
}

############################################################
# Swap setup with validation
############################################################
setup_swap() {
  log_info "Checking swap configuration..."
  
  if [ "$PI_MEMORY" -gt 512 ]; then
    log_info "Sufficient memory (${PI_MEMORY}MB), swap adjustment not needed"
    return
  fi
  
  log_info "Low memory detected (${PI_MEMORY}MB). Checking swap..."
  
  local current_swap
  current_swap=$(free -m | awk '/^Swap:/ {print $2}')
  
  if ! validate_number "$current_swap"; then
    log_warning "Could not determine current swap size"
    return
  fi
  
  if [ "$current_swap" -ge 1024 ]; then
    log_info "Swap already adequate (${current_swap}MB)"
    return
  fi
  
  log_warning "Current swap is ${current_swap}MB"
  
  if ! prompt_yn "Increase swap to 1024MB for package compilation? (y/n): " y; then
    log_info "Keeping current swap configuration"
    return
  fi
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would increase swap to 1024MB"
    return
  fi
  
  log_info "Setting up swap file..."
  
  # Turn off existing swap
  sudo dphys-swapfile swapoff 2>/dev/null || true
  
  # Update configuration
  if [ -f /etc/dphys-swapfile ]; then
    sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile
  else
    echo "CONF_SWAPSIZE=1024" | sudo tee /etc/dphys-swapfile >/dev/null
  fi
  
  # Create and enable swap
  if sudo dphys-swapfile setup && sudo dphys-swapfile swapon; then
    log_success "Swap increased to 1024MB"
    
    # Verify
    local new_swap
    new_swap=$(free -m | awk '/^Swap:/ {print $2}')
    log_info "Current swap: ${new_swap}MB"
  else
    log_error "Failed to set up swap"
  fi
}

############################################################
# Piwheels configuration
############################################################
setup_piwheels() {
  log_info "Configuring piwheels for faster Python package installation..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would configure piwheels in ~/.pip/pip.conf"
    return
  fi
  
  mkdir -p ~/.pip
  
  if [ -f ~/.pip/pip.conf ] && grep -q "piwheels" ~/.pip/pip.conf; then
    log_info "Piwheels already configured"
    return
  fi
  
  cat > ~/.pip/pip.conf <<'EOF'
[global]
extra-index-url=https://www.piwheels.org/simple
EOF
  
  chmod 600 ~/.pip/pip.conf
  log_success "Piwheels configured in ~/.pip/pip.conf"
}

############################################################
# Progress indicator with process monitoring
############################################################
show_progress() {
  local pid=$1
  local message=$2
  local elapsed=0
  
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${CYAN}[PROGRESS]${NC} %s... %d seconds elapsed" "$message" "$elapsed"
    sleep 5
    elapsed=$((elapsed + 5))
    
    # Temperature check with cooldown if needed
    if ! check_temperature; then
      sleep 20
    fi
  done
  
  wait "$pid"
  local exit_code=$?
  
  printf "\r${CYAN}[PROGRESS]${NC} %s... Complete! (%d seconds)          \n" "$message" "$elapsed"
  
  return $exit_code
}

############################################################
# VNC Server setup
############################################################
setup_vnc() {
  log_info "Setting up VNC server..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would install and configure VNC server"
    log_info "[DRY-RUN] Would open firewall port 5900"
    return
  fi
  
  # Install RealVNC server (usually pre-installed on Raspberry Pi OS)
  if ! command -v vncserver >/dev/null 2>&1; then
    log_info "Installing RealVNC server..."
    if ! sudo apt-get install -y realvnc-vnc-server; then
      log_warning "Failed to install RealVNC, trying TigerVNC..."
      if ! sudo apt-get install -y tigervnc-standalone-server tigervnc-common; then
        log_error "Failed to install VNC server"
        return 1
      fi
    fi
  fi
  
  # Enable VNC via raspi-config if available
  if command -v raspi-config >/dev/null 2>&1; then
    log_info "Enabling VNC via raspi-config..."
    sudo raspi-config nonint do_vnc 0 || log_warning "Could not enable VNC via raspi-config"
  fi
  
  # Enable VNC server service
  if systemctl list-unit-files | grep -q vncserver-x11-serviced; then
    sudo systemctl enable vncserver-x11-serviced.service || true
    sudo systemctl start vncserver-x11-serviced.service || true
    log_success "VNC server service enabled"
  fi
  
  # Configure firewall for VNC
  log_info "Configuring firewall for VNC (port 5900)..."
  if sudo ufw allow 5900/tcp comment 'VNC Server'; then
    log_success "Firewall configured for VNC (port 5900)"
  else
    log_warning "Could not configure firewall for VNC"
  fi
  
  # Check if VNC is listening
  sleep 2
  if ss -tln 2>/dev/null | grep -q ':5900'; then
    log_success "VNC server is running on port 5900"
    local ip_addr
    ip_addr=$(hostname -I | awk '{print $1}')
    log_info "Connect with VNC client to: ${ip_addr}:5900"
  else
    log_warning "VNC server may not be running yet"
    log_info "Try rebooting or manually start with: vncserver"
  fi
  
  VNC_ENABLED=1
}

############################################################
# Package installation with retry logic
############################################################
install_packages() {
  local package_list=("$@")
  local max_retries=3
  local attempt=1
  
  if [ ${#package_list[@]} -eq 0 ]; then
    log_warning "No packages to install"
    return 0
  fi
  
  log_info "Installing packages: ${package_list[*]}"
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would install: ${package_list[*]}"
    return 0
  fi
  
  while [ $attempt -le $max_retries ]; do
    if sudo apt-get install -y "${package_list[@]}"; then
      log_success "Packages installed successfully"
      return 0
    fi
    
    log_warning "Package installation failed (attempt $attempt/$max_retries)"
    
    if [ $attempt -eq $max_retries ]; then
      log_error "Failed to install packages after $max_retries attempts"
      log_error "Failed packages: ${package_list[*]}"
      return 1
    fi
    
    log_info "Retrying in 5 seconds..."
    sleep 5
    
    # Try to fix broken packages
    sudo apt-get --fix-broken install -y || true
    sudo apt-get update -y || true
    
    attempt=$((attempt + 1))
  done
  
  return 1
}

############################################################
# Initialize logging and acquire lock
############################################################
setup_logging
acquire_lock

############################################################
# Verify script integrity
############################################################
verify_script_integrity

############################################################
# Main banner
############################################################
clear
cat << "EOF"
╔════════════════════════════════════════╗
║  Universal Raspberry Pi Setup Script  ║
║     Enhanced Security Edition          ║
╚════════════════════════════════════════╝
EOF
echo ""
log_info "Version: $SCRIPT_VERSION"
log_info "Log file: $LOG_FILE"
echo ""

if [ "$DRY_RUN" -eq 1 ]; then
  log_warning "DRY-RUN MODE: No changes will be made"
  echo ""
fi

############################################################
# Recovery / Resume
############################################################
LAST_CHECKPOINT=$(load_checkpoint)

if [ "$LAST_CHECKPOINT" != "START" ] && [ "$LAST_CHECKPOINT" != "COMPLETE" ] && [ "$FORCE_RERUN" -eq 0 ]; then
  log_warning "Previous installation was interrupted at: $LAST_CHECKPOINT"
  
  if prompt_yn "Resume from last checkpoint? (y/n): " y; then
    log_info "Resuming from checkpoint: $LAST_CHECKPOINT"
  else
    log_info "Starting fresh installation"
    clear_checkpoint
    LAST_CHECKPOINT="START"
  fi
else
  LAST_CHECKPOINT="START"
fi

############################################################
# Check for completed installation
############################################################
if load_state && [ "$FORCE_RERUN" -eq 0 ] && [ "$LAST_CHECKPOINT" = "COMPLETE" ]; then
  log_info "Previous installation detected:"
  log_info "  Profile: $PROFILE ($PROFILE_ABBREV)"
  log_info "  Tier: $PERF_TIER"
  log_info "  Hostname: $HOSTNAME"
  log_info "  Date: $INSTALL_DATE"
  log_info "  VNC: $([ "$VNC_ENABLED" -eq 1 ] && echo 'Enabled' || echo 'Disabled')"
  echo ""
  
  if prompt_yn "Would you like to switch to a different profile? (y/n): " n; then
    log_info "Profile switching mode activated"
    detect_pi_info
    select_profile
    
    if [ "$PROFILE" != "$(grep PROFILE= "$STATE_FILE" 2>/dev/null | cut -d= -f2)" ]; then
      log_info "Switching to profile: $PROFILE"
      LAST_CHECKPOINT="PROFILE"
    else
      log_info "Same profile selected, no changes needed"
      exit 0
    fi
  else
    log_info "Setup already completed. Use --force to rerun"
    exit 0
  fi
fi

############################################################
# Locale Setup
############################################################
if ! is_checkpoint_passed "LOCALE"; then
  if ! setup_locale; then
    log_error "Locale setup failed"
    exit 1
  fi
  save_checkpoint "LOCALE"
fi

############################################################
# Hardware Detection
############################################################
if ! is_checkpoint_passed "DETECT"; then
  detect_pi_info
  
  # Verify we're on a Raspberry Pi
  if [ -f /proc/device-tree/model ]; then
    if ! grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
      log_warning "This doesn't appear to be a Raspberry Pi"
      log_warning "Detected: $(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')"
      
      if ! prompt_yn "Continue anyway? (y/n): " n; then
        log_info "Setup cancelled"
        exit 0
      fi
    fi
  fi
  
  select_pi_model
  select_profile
  save_checkpoint "DETECT"
fi

############################################################
# Hostname Configuration
############################################################
if ! is_checkpoint_passed "HOSTNAME"; then
  set_hostname
  save_checkpoint "HOSTNAME"
fi

############################################################
# Network Configuration
############################################################
if ! is_checkpoint_passed "NETWORK"; then
  configure_network
  save_checkpoint "NETWORK"
fi

############################################################
# Swap Setup
############################################################
if ! is_checkpoint_passed "SWAP"; then
  if [[ "$PERF_TIER" == "LOW" || "$PERF_TIER" == "MINIMAL" ]]; then
    setup_swap
  fi
  save_checkpoint "SWAP"
fi

############################################################
# System Update
############################################################
if ! is_checkpoint_passed "UPDATE"; then
  log_info "Updating package lists..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would run: sudo apt-get update"
  else
    if ! sudo apt-get update -y; then
      log_error "Failed to update package lists"
      log_error "Check your network connection and /etc/apt/sources.list"
      exit 1
    fi
  fi
  
  save_checkpoint "UPDATE"
fi

############################################################
# System Upgrade
############################################################
if ! is_checkpoint_passed "UPGRADE"; then
  if [[ "$PERF_TIER" == "MINIMAL" ]]; then
    log_warning "Very low memory detected (${PI_MEMORY}MB). Upgrade will be slow."
    
    if ! prompt_yn "Proceed with full system upgrade? (y/n): " y; then
      log_info "Skipping upgrade. You can run 'sudo apt upgrade' later."
      save_checkpoint "UPGRADE"
    else
      log_info "Upgrading packages (this may take 30-60 minutes)..."
      
      if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[DRY-RUN] Would run: sudo apt-get upgrade"
      else
        sudo apt-get upgrade -y &
        show_progress $! "Upgrading system packages"
        
        if [ $? -ne 0 ]; then
          log_error "System upgrade failed"
          exit 1
        fi
      fi
      
      save_checkpoint "UPGRADE"
    fi
  else
    log_info "Upgrading installed packages (this may take a while)..."
    
    if [ "$DRY_RUN" -eq 1 ]; then
      log_info "[DRY-RUN] Would run: sudo apt-get upgrade"
    else
      if [[ "$PERF_TIER" == "LOW" ]]; then
        sudo apt-get upgrade -y &
        show_progress $! "Upgrading system packages"
        
        if [ $? -ne 0 ]; then
          log_error "System upgrade failed"
          exit 1
        fi
      else
        if ! sudo apt-get upgrade -y; then
          log_error "System upgrade failed"
          exit 1
        fi
      fi
    fi
    
    save_checkpoint "UPGRADE"
  fi
  
  check_temperature
fi

############################################################
# Essential Packages
############################################################
if ! is_checkpoint_passed "ESSENTIAL"; then
  log_info "Installing essential packages for $PERF_TIER tier system..."
  
  ESSENTIAL_PACKAGES=(
    curl wget git vim htop tree unzip
    apt-transport-https ca-certificates gnupg
    lsb-release net-tools ufw arping
  )
  
  # Add build tools for higher tiers
  if [[ "$PERF_TIER" != "MINIMAL" ]]; then
    ESSENTIAL_PACKAGES+=(build-essential)
  fi
  
  # Add Python based on tier
  if [[ "$PERF_TIER" == "HIGH" || "$PERF_TIER" == "MEDIUM" ]]; then
    ESSENTIAL_PACKAGES+=(python3-pip python3-venv python3-dev)
  elif [[ "$PERF_TIER" == "LOW" ]]; then
    ESSENTIAL_PACKAGES+=(python3-pip python3-venv)
  else
    ESSENTIAL_PACKAGES+=(python3)
  fi
  
  # Node.js for high/medium tier (not ARMv6)
  if [[ "$PERF_TIER" == "HIGH" || "$PERF_TIER" == "MEDIUM" ]]; then
    if [[ "$PI_ARCH" != "armv6l" ]]; then
      if prompt_yn "Install Node.js and npm? (not available for ARMv6) (y/n): " n; then
        ESSENTIAL_PACKAGES+=(nodejs npm)
      fi
    fi
  fi
  
  if ! install_packages "${ESSENTIAL_PACKAGES[@]}"; then
    log_error "Failed to install essential packages"
    exit 1
  fi
  
  save_checkpoint "ESSENTIAL"
  check_temperature
fi

############################################################
# Security Setup
############################################################
if ! is_checkpoint_passed "SECURITY"; then
  log_info "Setting up basic firewall (UFW)..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would configure UFW firewall"
  else
    # Configure rules BEFORE enabling firewall
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh comment 'SSH'
    
    # Enable firewall
    sudo ufw --force enable
    
    log_success "Firewall configured (SSH allowed)"
  fi
  
  # Ensure SSH is enabled
  if ! systemctl is-active --quiet ssh 2>/dev/null; then
    log_info "Enabling SSH service..."
    
    if [ "$DRY_RUN" -eq 1 ]; then
      log_info "[DRY-RUN] Would enable SSH service"
    else
      sudo systemctl enable --now ssh
      log_success "SSH enabled and started"
    fi
  else
    log_info "SSH service already running"
  fi
  
  save_checkpoint "SECURITY"
fi

############################################################
# VNC Setup
############################################################
if ! is_checkpoint_passed "VNC"; then
  if [ "$ENABLE_VNC" -eq 1 ] || prompt_yn "Would you like to enable VNC server? (y/n): " n; then
    setup_vnc
  else
    log_info "Skipping VNC setup"
    VNC_ENABLED=0
  fi
  
  save_checkpoint "VNC"
fi

############################################################
# Git Configuration
############################################################
if ! is_checkpoint_passed "GIT"; then
  if prompt_yn "Would you like to configure Git? (y/n): " n; then
    local git_username git_email
    
    git_username=$(read_tty "Enter your Git username: " "")
    git_email=$(read_tty "Enter your Git email: " "")
    
    if [ -n "$git_username" ] && [ -n "$git_email" ]; then
      if validate_email "$git_email"; then
        if [ "$DRY_RUN" -eq 1 ]; then
          log_info "[DRY-RUN] Would configure Git with:"
          log_info "  Name: $git_username"
          log_info "  Email: $git_email"
        else
          git config --global user.name "$git_username"
          git config --global user.email "$git_email"
          git config --global init.defaultBranch main
          git config --global pull.rebase false
          log_success "Git configured successfully"
        fi
      else
        log_warning "Invalid email format, skipping Git configuration"
      fi
    else
      log_warning "Git configuration skipped (empty values)"
    fi
  fi
  
  save_checkpoint "GIT"
fi

############################################################
# Email Setup (secure with GPG)
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
      
      if ! install_packages msmtp msmtp-mta gpg; then
        log_warning "Failed to install email packages"
      else
        mkdir -p ~/.secrets
        chmod 700 ~/.secrets
        
        local email_address
        email_address=$(read_tty "Enter your Gmail address: " "")
        
        if [ -n "$email_address" ] && validate_email "$email_address"; then
          log_warning "You need a Gmail App Password (not your regular password)"
          log_info "Create one at: https://myaccount.google.com/apppasswords"
          echo ""
          
          local app_password
          app_password=$(read_secure "Enter your Gmail App Password (16 chars, no spaces): ")
          
          if [ -n "$app_password" ] && [ ${#app_password} -ge 16 ]; then
            if [ "$DRY_RUN" -eq 1 ]; then
              log_info "[DRY-RUN] Would configure msmtp for $email_address"
            else
              # Encrypt password with GPG
              printf "%s" "$app_password" | gpg --batch --yes --symmetric --cipher-algo AES256 -o ~/.secrets/msmtp.gpg 2>/dev/null
              
              # Clear password from memory
              app_password=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64)
              unset app_password
              
              chmod 600 ~/.secrets/msmtp.gpg
              
              # Create msmtp configuration
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
              if echo "Test email from Raspberry Pi $(hostname) at $(date)" | msmtp "$email_address" 2>/dev/null; then
                log_success "Email configured and tested successfully!"
                log_info "Check your inbox (or spam folder) for the test email"
              else
                log_warning "Email configured but test failed - check ~/.msmtp.log for details"
                log_info "You can test manually with: echo 'test' | msmtp $email_address"
              fi
            fi
          else
            log_warning "Email configuration skipped (invalid app password)"
          fi
        else
          log_warning "Email configuration skipped (invalid email address)"
        fi
      fi
    fi
  fi
  
  save_checkpoint "EMAIL"
fi

############################################################
# Raspi-config
############################################################
if ! is_checkpoint_passed "RASPI_CONFIG"; then
  if command -v raspi-config &>/dev/null; then
    log_info "Configuring Raspberry Pi specific settings..."
    
    # Expand filesystem
    log_info "Expanding filesystem to use full SD card..."
    if [ "$DRY_RUN" -eq 1 ]; then
      log_info "[DRY-RUN] Would expand root filesystem"
    else
      if sudo raspi-config nonint do_expand_rootfs; then
        log_success "Filesystem expansion configured (reboot required)"
      else
        log_warning "Expansion may have already been performed"
      fi
    fi
    
    # GPU memory allocation
    if prompt_yn "Allocate GPU memory? (y/n): " n; then
      local gpu_mem
      
      if [[ "$PERF_TIER" == "MINIMAL" || "$PERF_TIER" == "LOW" ]]; then
        gpu_mem=$(read_tty "GPU memory in MB [16/32/64] (default: 16): " "16")
      else
        gpu_mem=$(read_tty "GPU memory in MB [64/128/256] (default: 128): " "128")
      fi
      
      if validate_number "$gpu_mem" 16 512; then
        local config_file
        if [ -f /boot/firmware/config.txt ]; then
          config_file="/boot/firmware/config.txt"
        elif [ -f /boot/config.txt ]; then
          config_file="/boot/config.txt"
        else
          log_warning "Could not find config.txt"
          config_file=""
        fi
        
        if [ -n "$config_file" ]; then
          if [ "$DRY_RUN" -eq 1 ]; then
            log_info "[DRY-RUN] Would set gpu_mem=$gpu_mem in $config_file"
          else
            if grep -q "^gpu_mem=" "$config_file" 2>/dev/null; then
              sudo sed -i "s/^gpu_mem=.*/gpu_mem=$gpu_mem/" "$config_file"
            else
              echo "gpu_mem=$gpu_mem" | sudo tee -a "$config_file" >/dev/null
            fi
            log_success "GPU memory set to ${gpu_mem}MB (requires reboot)"
          fi
        fi
      else
        log_warning "Invalid GPU memory value, skipping"
      fi
    fi
    
    # Hardware interfaces
    if prompt_yn "Enable I2C interface? (y/n): " n; then
      if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[DRY-RUN] Would enable I2C"
      else
        sudo raspi-config nonint do_i2c 0
        log_success "I2C enabled"
      fi
    fi
    
    if prompt_yn "Enable SPI interface? (y/n): " n; then
      if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[DRY-RUN] Would enable SPI"
      else
        sudo raspi-config nonint do_spi 0
        log_success "SPI enabled"
      fi
    fi
    
    if prompt_yn "Enable Camera interface? (y/n): " n; then
      if [ "$DRY_RUN" -eq 1 ]; then
        log_info "[DRY-RUN] Would enable Camera"
      else
        sudo raspi-config nonint do_camera 0
        log_success "Camera enabled"
      fi
    fi
  else
    log_warning "raspi-config not found, skipping Pi-specific configuration"
  fi
  
  save_checkpoint "RASPI_CONFIG"
fi

############################################################
# Python Setup
############################################################
if ! is_checkpoint_passed "PYTHON"; then
  if [[ "$PERF_TIER" != "MINIMAL" ]]; then
    setup_piwheels
    
    if prompt_yn "Install Python packages? (y/n): " y; then
      log_info "Installing Python packages for $PERF_TIER tier system..."
      
      PYTHON_PACKAGES=()
      
      if [[ "$PERF_TIER" == "LOW" ]]; then
        log_warning "Installing only lightweight Python packages for low-spec Pi"
        PYTHON_PACKAGES+=(requests RPi.GPIO)
        
        if prompt_yn "Install Flask? (y/n): " n; then
          PYTHON_PACKAGES+=(flask)
        fi
      elif [[ "$PERF_TIER" == "MEDIUM" ]]; then
        PYTHON_PACKAGES+=(requests flask RPi.GPIO)
        
        if prompt_yn "Install numpy? (y/n): " n; then
          PYTHON_PACKAGES+=(numpy)
        fi
        
        if prompt_yn "Install Adafruit libraries? (y/n): " n; then
          PYTHON_PACKAGES+=(adafruit-circuitpython-motor adafruit-circuitpython-servo)
        fi
      else
        PYTHON_PACKAGES+=(numpy requests flask RPi.GPIO)
        PYTHON_PACKAGES+=(adafruit-circuitpython-motor adafruit-circuitpython-servo)
        
        if prompt_yn "Install matplotlib? (y/n): " n; then
          PYTHON_PACKAGES+=(matplotlib)
        fi
      fi
      
      if [ ${#PYTHON_PACKAGES[@]} -gt 0 ]; then
        log_info "Installing: ${PYTHON_PACKAGES[*]}"
        
        if [[ "$PERF_TIER" == "LOW" ]]; then
          log_warning "Installation may take 5-15 minutes with piwheels..."
        fi
        
        if [ "$DRY_RUN" -eq 1 ]; then
          log_info "[DRY-RUN] Would install Python packages: ${PYTHON_PACKAGES[*]}"
        else
          if pip3 install --user --no-warn-script-location "${PYTHON_PACKAGES[@]}"; then
            log_success "Python packages installed"
            
            # Add to PATH
            if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc; then
              echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
            fi
          else
            log_warning "Some Python packages may have failed to install"
            log_info "Retry later with: pip3 install --user <package>"
          fi
        fi
      fi
    fi
  else
    log_info "Skipping Python packages for MINIMAL tier"
  fi
  
  save_checkpoint "PYTHON"
  check_temperature
fi

############################################################
# Profile-specific Installations
############################################################
if ! is_checkpoint_passed "PROFILE"; then
  log_info "Installing profile-specific packages: $PROFILE"
  
  case $PROFILE in
    web)
      log_info "Installing web server stack..."
      
      if [[ "$PERF_TIER" == "MINIMAL" ]]; then
        log_warning "Web server profile not recommended for MINIMAL tier"
        
        if prompt_yn "Continue anyway? (y/n): " n; then
          if install_packages nginx php-fpm sqlite3 php-sqlite3; then
            if [ "$DRY_RUN" -eq 0 ]; then
              sudo systemctl enable nginx
              sudo systemctl start nginx
              sudo ufw allow 'Nginx HTTP'
            fi
            log_success "Nginx + PHP + SQLite installed"
          fi
        else
          log_info "Skipping web server installation"
        fi
      else
        if install_packages nginx php-fpm mariadb-server php-mysql; then
          if [ "$DRY_RUN" -eq 0 ]; then
            sudo systemctl enable nginx mariadb
            sudo systemctl start nginx mariadb
            sudo ufw allow 'Nginx HTTP'
            log_success "Web server stack installed (Nginx + PHP + MariaDB)"
            log_info "Secure MariaDB with: sudo mysql_secure_installation"
          else
            log_info "[DRY-RUN] Would enable and start web services"
          fi
        fi
      fi
      ;;
      
    iot)
      log_info "Installing IoT sensor stack..."
      
      if install_packages mosquitto mosquitto-clients; then
        if [ "$DRY_RUN" -eq 0 ]; then
          if [[ "$PERF_TIER" != "MINIMAL" ]]; then
            pip3 install --user paho-mqtt adafruit-blinka || log_warning "Some IoT packages failed"
          fi
          
          sudo systemctl enable mosquitto
          sudo systemctl start mosquitto
          sudo ufw allow 1883 comment 'MQTT'
          log_success "IoT stack installed (MQTT broker + clients)"
        else
          log_info "[DRY-RUN] Would enable MQTT and install Python IoT packages"
        fi
      fi
      ;;
      
    media)
      log_info "Installing media center tools..."
      
      if [[ "$PERF_TIER" == "MINIMAL" ]]; then
        install_packages omxplayer
      else
        install_packages vlc mpv youtube-dl ffmpeg
      fi
      
      log_success "Media tools installed"
      ;;
      
    dev)
      log_info "Installing development environment..."
      
      DEV_PACKAGES=(tmux screen)
      
      if [[ "$PERF_TIER" != "MINIMAL" ]]; then
        DEV_PACKAGES+=(docker.io docker-compose)
      fi
      
      if install_packages "${DEV_PACKAGES[@]}"; then
        if [ "$DRY_RUN" -eq 0 ]; then
          if command -v docker &>/dev/null; then
            sudo usermod -aG docker "$USER"
            log_success "Added $USER to docker group (logout required)"
          fi
          log_success "Development environment installed"
        else
          log_info "[DRY-RUN] Would configure Docker access"
        fi
      fi
      ;;
      
    generic)
      log_info "Generic profile - no additional packages"
      ;;
  esac
  
  save_checkpoint "PROFILE"
  check_temperature
fi

############################################################
# Directories and Aliases
############################################################
if ! is_checkpoint_passed "ALIASES"; then
  log_info "Creating useful directories..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would create ~/projects ~/scripts ~/backup ~/logs"
  else
    mkdir -p ~/projects ~/scripts ~/backup ~/logs
  fi
  
  log_info "Setting up useful aliases..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would add aliases to ~/.bashrc"
  else
    if ! grep -q "# === Custom Aliases ===" ~/.bashrc; then
      cat >> ~/.bashrc <<'EOF'

# === Custom Aliases ===
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'
alias ..='cd ..'
alias ...='cd ../..'
alias grep='grep --color=auto'
alias temp='vcgencmd measure_temp'
alias cpu='cat /proc/cpuinfo | grep "model name" | head -1'
alias memory='free -h'
alias disk='df -h'
alias gs='git status'
alias ga='git add'
alias gc='git commit -m'
alias gp='git push'
alias gl='git log --oneline --graph --decorate'
alias gd='git diff'
alias processes='ps aux | head -20'
alias ports='netstat -tuln'
alias update='sudo apt update && sudo apt upgrade -y'
alias sysinfo='~/scripts/sysinfo.sh'
alias profile='cat ~/.rpi_setup_state'
alias logs='tail -f ~/.rpi_setup.log'

EOF
      log_success "Aliases added to ~/.bashrc"
    else
      log_info "Aliases already exist in ~/.bashrc"
    fi
  fi
  
  # Create system info script
  log_info "Creating system info script..."
  
  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would create ~/scripts/sysinfo.sh"
  else
    cat > ~/scripts/sysinfo.sh <<'EOF'
#!/bin/bash
echo "=========================================="
echo "=== Raspberry Pi System Information ==="
echo "=========================================="
echo "Hostname:      $(hostname)"
echo "Model:         $(cat /proc/device-tree/model 2>/dev/null | tr -d '\0' || echo 'N/A')"
echo "Serial:        $(grep Serial /proc/cpuinfo | awk '{print $3}' || echo 'N/A')"
echo "OS:            $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "Kernel:        $(uname -r)"
echo "Architecture:  $(uname -m)"
echo "Uptime:        $(uptime -p)"
echo "Temperature:   $(vcgencmd measure_temp 2>/dev/null || echo 'N/A')"
echo "Memory Usage:  $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "Swap Usage:    $(free -h | awk '/^Swap:/ {print $3 "/" $2}')"
echo "Disk Usage:    $(df -h / | awk '/\// {print $3 "/" $2 " (" $5 ")"}')"
echo "Load Average:  $(uptime | awk -F'load average:' '{print $2}')"
echo "IP Address:    $(hostname -I | awk '{print $1}')"
echo "SSH Status:    $(systemctl is-active ssh 2>/dev/null || echo 'unknown')"
echo "Firewall:      $(sudo ufw status 2>/dev/null | head -1 || echo 'unknown')"
if [ -f ~/.rpi_setup_state ]; then
  echo "---"
  echo "Setup Profile: $(grep PROFILE= ~/.rpi_setup_state | cut -d= -f2)"
  echo "Setup Date:    $(grep INSTALL_DATE= ~/.rpi_setup_state | cut -d= -f2)"
  echo "VNC Enabled:   $(grep VNC_ENABLED= ~/.rpi_setup_state | cut -d= -f2)"
fi
echo "=========================================="
EOF
    chmod +x ~/scripts/sysinfo.sh
    log_success "System info script created at ~/scripts/sysinfo.sh"
  fi
  
  # Performance tips for low-spec systems
  if [[ "$PERF_TIER" == "LOW" || "$PERF_TIER" == "MINIMAL" ]]; then
    log_info "Creating performance tips file..."
    
    if [ "$DRY_RUN" -eq 1 ]; then
      log_info "[DRY-RUN] Would create ~/LOW_SPEC_TIPS.txt"
    else
      cat > ~/LOW_SPEC_TIPS.txt <<'EOF'
=== Performance Tips for Low-Spec Raspberry Pi ===

1. Memory Management:
   - Monitor memory: free -h
   - Check swap: swapon --show
   - Kill unnecessary processes: sudo systemctl disable <service>

2. Reduce Services:
   - Disable Bluetooth: sudo systemctl disable bluetooth
   - Disable WiFi if using Ethernet: sudo rfkill block wifi
   - Check running services: systemctl list-units --type=service --state=running

3. Storage Optimization:
   - Clear apt cache: sudo apt-get clean
   - Remove old kernels: sudo apt-get autoremove
   - Check disk usage: ncdu /

4. Overclocking (Use with caution!):
   - Edit /boot/config.txt or /boot/firmware/config.txt
   - Add: arm_freq=1000 (adjust based on your model)
   - Monitor temperature: watch -n 1 vcgencmd measure_temp

5. Headless Operation:
   - Disable GUI: sudo systemctl set-default multi-user.target
   - Re-enable GUI: sudo systemctl set-default graphical.target
   - This frees up ~200MB RAM

6. Profile Switching:
   - You can switch profiles anytime: ./setup_script.sh --force
   - Or manually update: vim ~/.rpi_setup_state

7. Monitoring:
   - Install htop: sudo apt install htop
   - Monitor temperature: watch vcgencmd measure_temp
   - Check throttling: vcgencmd get_throttled

8. Power Management:
   - Use quality power supply (5V 2.5A minimum)
   - Check for under-voltage: vcgencmd get_throttled
   - If throttled (0x50000): upgrade power supply

For more tips, visit: https://www.raspberrypi.org/documentation/
EOF
      log_success "Performance tips saved to ~/LOW_SPEC_TIPS.txt"
    fi
  fi
  
  save_checkpoint "ALIASES"
fi

############################################################
# Save Final State
############################################################
save_state

############################################################
# Cleanup
############################################################
if [ "$DRY_RUN" -eq 0 ]; then
  log_info "Cleaning up package cache..."
  sudo apt-get autoremove -y
  sudo apt-get autoclean
fi

############################################################
# Mark as Complete
############################################################
save_checkpoint "COMPLETE"
clear_checkpoint

############################################################
# System Info Report
############################################################
log_info "Running system information reporter..."
echo ""

if [ "$DRY_RUN" -eq 1 ]; then
  log_info "[DRY-RUN] Would fetch and run system info reporter"
else
  if command -v curl &>/dev/null; then
    log_info "Fetching system info script..."
    
    # Check if email is configured
    if [ -f ~/.msmtprc ]; then
      EMAIL_ADDR=$(grep "^from" ~/.msmtprc | awk '{print $2}')
      log_info "Using configured email: $EMAIL_ADDR"
      
      if curl -fsSL https://raw.githubusercontent.com/mmlawless/mml_rpi_info/main/mml_rpi_info.sh | bash -s -- --email "$EMAIL_ADDR"; then
        log_success "System info report sent successfully"
      else
        log_warning "System info report failed - you can run it manually later"
        log_info "Command: curl -fsSL https://raw.githubusercontent.com/mmlawless/mml_rpi_info/main/mml_rpi_info.sh | bash -s -- --email YOUR_EMAIL"
      fi
    else
      if [ "$NON_INTERACTIVE" -eq 0 ]; then
        if prompt_yn "Send system info report via email? (y/n): " n; then
          local report_email
          report_email=$(read_tty "Enter email address for report: " "")
          
          if [ -n "$report_email" ] && validate_email "$report_email"; then
            if curl -fsSL https://raw.githubusercontent.com/mmlawless/mml_rpi_info/main/mml_rpi_info.sh | bash -s -- --email "$report_email"; then
              log_success "System info report sent to $report_email"
            else
              log_warning "System info report failed"
            fi
          else
            log_info "Invalid email, skipping system info report"
          fi
        else
          log_info "Skipping system info report"
        fi
      else
        log_info "Non-interactive mode, skipping system info report"
      fi
    fi
  else
    log_warning "curl not available, skipping system info report"
  fi
fi

echo ""

############################################################
# Summary and Reboot Prompt
############################################################
echo ""
echo "=========================================="
log_success "Raspberry Pi setup completed successfully!"
echo "=========================================="
echo ""
echo "Configuration Summary:"
echo "  - Hostname: $NEW_HOSTNAME"
echo "  - Model: Raspberry Pi $PI_MODEL"
echo "  - Serial: $PI_SERIAL"
echo "  - Memory: ${PI_MEMORY}MB RAM"
echo "  - Performance Tier: $PERF_TIER"
echo "  - Architecture: $PI_ARCH"
echo "  - Profile: $PROFILE ($PROFILE_ABBREV)"
echo "  - VNC Server: $([ "$VNC_ENABLED" -eq 1 ] && echo 'Enabled (port 5900)' || echo 'Disabled')"

if [ -f ~/.msmtprc ]; then
  echo "  - Email: Configured"
fi

if [[ "$PERF_TIER" == "LOW" || "$PERF_TIER" == "MINIMAL" ]]; then
  echo "  - Performance tips: ~/LOW_SPEC_TIPS.txt"
fi

echo ""
echo "Useful commands:"
echo "  sysinfo           - Show detailed system information"
echo "  profile           - Show current setup profile"
echo "  temp              - Show CPU temperature"
echo "  update            - Update and upgrade packages"
echo "  logs              - View setup log file"

if [ "$VNC_ENABLED" -eq 1 ]; then
  echo ""
  local vnc_ip
  vnc_ip=$(hostname -I | awk '{print $1}')
  echo "VNC Connection:"
  echo "  Address: ${vnc_ip}:5900"
  echo "  or: ${NEW_HOSTNAME}.local:5900"
fi

echo ""
echo "Log file: $LOG_FILE"
echo ""

log_warning "IMPORTANT: Reboot required to finalize all changes"
log_info "New hostname ($NEW_HOSTNAME) will be active after reboot"

if [ "$VNC_ENABLED" -eq 1 ]; then
  log_info "VNC server will be fully active after reboot"
fi

echo ""

if [ "$DRY_RUN" -eq 1 ]; then
  log_info "[DRY-RUN] Setup complete - no actual changes were made"
  exit 0
fi

if prompt_yn "Would you like to reboot now? (y/n): " n; then
  log_info "Rebooting in 5 seconds... (Ctrl+C to cancel)"
  sleep 5
  sudo reboot
else
  log_info "Please remember to reboot when convenient: sudo reboot"
  
  if [[ "$PERF_TIER" == "LOW" || "$PERF_TIER" == "MINIMAL" ]]; then
    log_info "After reboot, review performance tips in ~/LOW_SPEC_TIPS.txt"
  fi
  
  echo ""
  log_success "Setup complete! Enjoy your Raspberry Pi!"
fi
