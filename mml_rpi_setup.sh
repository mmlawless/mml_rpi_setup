#!/bin/bash
set -euo pipefail

############################################################
# Universal Raspberry Pi Setup Script
#
# Features: Enhanced security, validation, VNC support,
#           proper error handling, and comprehensive logging
#           + Robust static IP config (NM/dhcpcd, per-IF)
#           + Solid msmtp Gmail App Password flow
############################################################

SCRIPT_VERSION="2025-10-24-Universal-Secure"
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

  echo -e "${RED:-}[ERROR]${NC:-} Script exited with error code $exit_code" >&2
  if [ $exit_code -ne 0 ]; then
    echo -e "${RED:-}[ERROR]${NC:-} Check log file: $LOG_FILE" >&2
  fi

  exit $exit_code
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

# Register trap after colors are defined
trap cleanup EXIT INT TERM

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
PERF_TIER="${PERF_TIER:-MEDIUM}"

# Ensure Pi-related variables are always defined
PI_MODEL="${PI_MODEL:-unknown}"
PI_MEMORY="${PI_MEMORY:-0}"
PI_ARCH="${PI_ARCH:-$(uname -m)}"
PI_SERIAL="${PI_SERIAL:-UNKNOWN}"
NEW_HOSTNAME="${NEW_HOSTNAME:-$(hostname)}"

# Ensure NEW_HOSTNAME is always defined
NEW_HOSTNAME="$(hostname)"

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
      # shellcheck disable=SC1090
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
      MINIMAL|LOW|MEDIUM|HIGH) PERF_TIER="$PRESET_TIER"; log_info "Using preset tier: $PERF_TIER"; return ;;
      *) log_error "Invalid preset tier: $PRESET_TIER"; exit 1 ;;
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
      generic|web|iot|media|dev) PROFILE="$PRESET_PROFILE"; set_profile_abbrev; log_info "Using preset profile: $PROFILE"; return ;;
      *) log_error "Invalid preset profile: $PRESET_PROFILE"; exit 1 ;;
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
  local generated
  generated="LH-PI0x-${PI_MODEL}-${PI_SERIAL}-${PROFILE_ABBREV}-FUNC-IPA"

  CURRENT_HOSTNAME=$(hostname)
  log_info "Current hostname: $CURRENT_HOSTNAME"
  log_info "Proposed hostname: $generated"

  if [ "$DRY_RUN" -eq 1 ]; then
    log_info "[DRY-RUN] Would prompt for hostname (defaulting to proposed)"
    NEW_HOSTNAME="$generated"
  elif [ "$NON_INTERACTIVE" -eq 1 ]; then
    log_debug "Non-interactive: using proposed hostname"
    NEW_HOSTNAME="$generated"
  else
    local input
    input=$(read_tty "Enter desired hostname (leave empty to use proposed: $generated): " "")
    if [ -n "$input" ]; then
      if validate_hostname "$input"; then
        NEW_HOSTNAME="$input"
      else
        log_warning "Entered hostname '$input' is invalid. Falling back to generated hostname."
        NEW_HOSTNAME="$generated"
      fi
    else
      NEW_HOSTNAME="$generated"
    fi
  fi

  if ! validate_hostname "$NEW_HOSTNAME"; then
    log_warning "Final hostname '$NEW_HOSTNAME' invalid; using current hostname"
    NEW_HOSTNAME="$CURRENT_HOSTNAME"
  fi

  log_info "Hostname to set: $NEW_HOSTNAME"

  if [ "$CURRENT_HOSTNAME" = "$NEW_HOSTNAME" ]; then
    log_info "Hostname already correct"
    return
  fi

  if prompt_yn "Set hostname to $NEW_HOSTNAME? (y/n): " y; then
    if [ "$DRY_RUN" -eq 0 ]; then
      echo "$NEW_HOSTNAME" | sudo tee /etc/hostname >/dev/null
      if sudo grep -q "127.0.1.1" /etc/hosts 2>/dev/null; then
        sudo sed -i "s/^127.0.1.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts || true
      else
        echo -e "127.0.1.1\t$NEW_HOSTNAME" | sudo tee -a /etc/hosts >/dev/null
      fi
      sudo hostnamectl set-hostname "$NEW_HOSTNAME" 2>/dev/null || true
      log_success "Hostname set to $NEW_HOSTNAME"
    fi
  else
    NEW_HOSTNAME="$CURRENT_HOSTNAME"
  fi
}

############################################################
# Network helpers & Static IP configuration (UPDATED)
############################################################

# Increment last octet of IPv4 (bounds-checked)
increment_ip_last_octet() {
  local ip="$1"
  if ! validate_ip "$ip"; then echo ""; return 1; fi
  IFS='.' read -r a b c d <<< "$ip"
  if ! validate_number "$d" 0 254; then echo ""; return 1; fi
  d=$((d + 1))
  [ "$d" -gt 254 ] && { echo ""; return 1; }
  echo "${a}.${b}.${c}.${d}"
}

# Is IP locally assigned?
is_local_ip_assigned() {
  local ip="$1"
  ip addr show | grep -qw "$ip"
}

# Is IP in use on L2 (arping) or via ARP table
is_ip_in_use_on_network() {
  local ip="$1" iface="$2"
  if command -v arping >/dev/null 2>&1; then
    if sudo arping -c 2 -w 2 -I "${iface}" "${ip}" >/dev/null 2>&1; then
      return 0
    else
      return 1
    fi
  else
    ping -c 1 -W 1 "$ip" >/dev/null 2>&1 || true
    if ip neigh show | grep -wq "$ip"; then
      return 0
    else
      return 1
    fi
  fi
}

# NEW: Interface utilities
iface_exists() { ip link show dev "$1" >/dev/null 2>&1; }
iface_is_wireless() { [ -d "/sys/class/net/$1/wireless" ]; }
first_wireless_iface() {
  for i in /sys/class/net/*; do
    i="${i##*/}"
    [ "$i" = "lo" ] && continue
    iface_is_wireless "$i" && echo "$i" && return 0
  done
  return 1
}
iface_managed_by_nm() {
  nmcli -t -f DEVICE,STATE dev status 2>/dev/null \
    | awk -F: -v I="$1" '$1==I{ s=tolower($2); if (s!="unmanaged" && s!="unavailable") print "yes"; }' \
    | grep -q yes
}
nm_conn_for_iface() {
  local ifc="$1" name
  name="$(nmcli -t -f NAME,DEVICE con show --active 2>/dev/null | awk -F: -v I="$ifc" '$2==I{print $1; exit}')"
  [ -z "$name" ] && name="$(nmcli -t -f NAME,DEVICE con show 2>/dev/null | awk -F: -v I="$ifc" '$2==I{print $1; exit}')"
  echo "$name"
}
normalize_dns() { echo "$1" | tr ',' ' ' | xargs; } # commas -> spaces, trim

# Remove prior rpi-setup blocks for a specific iface from dhcpcd.conf
dhcpcd_remove_iface_block() {
  local IFACE="$1"
  sudo sed -i "/^# --- RPI_SETUP START: IFACE=${IFACE} ---/,/^# --- RPI_SETUP END: IFACE=${IFACE} ---/d" /etc/dhcpcd.conf
}

apply_static_nm() {
  local IFACE="$1" ADDR="$2" GW="$3" DNS="$4"
  local cname
  cname="$(nm_conn_for_iface "$IFACE")"
  if [ -n "$cname" ]; then
    log_info "Applying static IP to NM connection '$cname' ($IFACE)"
    nmcli con mod "$cname" ipv4.addresses "$ADDR" ipv4.gateway "$GW" ipv4.dns "$DNS" ipv4.method manual ipv6.method ignore || log_warning "Failed to modify $cname"
    # Bring down/up for ethernet; for wifi only if it already has credentials
    if ! iface_is_wireless "$IFACE"; then
      nmcli con down "$cname" >/dev/null 2>&1 || true
      nmcli con up "$cname"   >/dev/null 2>&1 || true
    else
      nmcli con reload >/dev/null 2>&1 || true
    fi
    log_success "Static IP set via NetworkManager for $IFACE: $ADDR"
  else
    log_warning "No NM connection bound to $IFACE; skipping NM config for it."
  fi
}

apply_static_dhcpcd() {
  local IFACE="$1" ADDR="$2" GW="$3" DNS="$4"
  [ -f /etc/dhcpcd.conf ] && sudo cp /etc/dhcpcd.conf /etc/dhcpcd.conf.bak.$(date +%s) || true
  dhcpcd_remove_iface_block "$IFACE"
  local block
  block=$(cat <<EOF

# --- RPI_SETUP START: IFACE=${IFACE} ---
# Static IP configuration added by mml_rpi_setup.sh on $(date)
interface ${IFACE}
static ip_address=${ADDR}
static routers=${GW}
static domain_name_servers=${DNS}
# --- RPI_SETUP END: IFACE=${IFACE} ---

EOF
)
  local tmpf
  tmpf="$(mktemp)"; echo "$block" >"$tmpf"
  sudo sh -c "cat >> /etc/dhcpcd.conf" <"$tmpf"; rm -f "$tmpf"
  if systemctl is-active --quiet dhcpcd 2>/dev/null; then
    log_info "Restarting dhcpcd..."
    sudo systemctl restart dhcpcd || log_warning "Failed to restart dhcpcd. Reboot may be required."
  else
    log_warning "dhcpcd service not active; ensure your OS uses dhcpcd for $IFACE."
  fi
  log_success "Static IP set for ${IFACE} via dhcpcd: ${ADDR}"
}

configure_network() {
  log_info "Network configuration..."

  # Discover default routed iface
  local default_iface
  default_iface="$(ip route get 8.8.8.8 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -n1)"
  default_iface="${default_iface:-eth0}"

  # Detect Ethernet + optional Wireless
  local ETH_IF WLAN_IF
  ETH_IF="$default_iface"; iface_exists "$ETH_IF" || ETH_IF="eth0"; iface_exists "$ETH_IF" || ETH_IF=""
  WLAN_IF="$(first_wireless_iface || true)"  # empty if none
  local CAN_PAIRED=0; [ -n "$ETH_IF" ] && [ -n "$WLAN_IF" ] && CAN_PAIRED=1

  if ! prompt_yn "Set static IPv4 address? (y/n): " n; then
    log_info "Keeping DHCP"
    return
  fi
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    log_warning "Non-interactive mode: skipping static configuration."
    return
  fi

  # Paired mode (only if both exist)
  if [ "$CAN_PAIRED" -eq 1 ] && prompt_yn "Configure both $ETH_IF and $WLAN_IF with $WLAN_IF = $ETH_IF+1? (y/n): " y; then
    local ip_cidr ip_only cidr_suffix wlan_ip wlan_cidr gateway dns dns_norm first_dns
    while true; do
      ip_cidr=$(read_tty "Static IP for ${ETH_IF} (CIDR, e.g. 192.168.1.201/24): " "")
      [ -z "$ip_cidr" ] && { log_warning "No IP provided, aborting static configuration"; return; }
      validate_cidr "$ip_cidr" && break || log_warning "Invalid CIDR. Please try again."
    done
    ip_only="${ip_cidr%%/*}"
    cidr_suffix="${ip_cidr#*/}"

    wlan_ip="$(increment_ip_last_octet "$ip_only")"
    [ -z "$wlan_ip" ] && { log_error "Failed to compute ${WLAN_IF} IP (overflow/invalid)"; return 1; }
    wlan_cidr="${wlan_ip}/${cidr_suffix}"

    while true; do
      gateway=$(read_tty "Gateway (router) IP (e.g. 192.168.1.1): " "")
      [ -z "$gateway" ] && { log_warning "No gateway provided, aborting"; return; }
      validate_ip "$gateway" && break || log_warning "Invalid IP. Try again."
    done
    while true; do
      dns=$(read_tty "DNS servers (comma/space separated, default: ${gateway}): " "${gateway}")
      dns_norm="$(normalize_dns "$dns")"
      first_dns="$(echo "$dns_norm" | awk '{print $1}')"
      validate_ip "$first_dns" && break || log_warning "Invalid DNS. Try again."
    done

    # Conflict checks (optional best-effort)
    if is_local_ip_assigned "$ip_only"; then
      log_warning "IP $ip_only already assigned locally."
      prompt_yn "Proceed anyway? (y/n): " n || { log_info "Aborting."; return; }
    fi
    if is_local_ip_assigned "$wlan_ip"; then
      log_warning "IP $wlan_ip already assigned locally."
      prompt_yn "Proceed anyway? (y/n): " n || { log_info "Aborting."; return; }
    fi
    if command -v arping >/dev/null 2>&1; then
      log_info "Checking for IP conflicts (arping) for $ETH_IF..."
      is_ip_in_use_on_network "$ip_only" "$ETH_IF" && log_warning "Another host may be using $ip_only on $ETH_IF."
      log_info "Checking for IP conflicts (arping) for $WLAN_IF..."
      is_ip_in_use_on_network "$wlan_ip" "$WLAN_IF" && log_warning "Another host may be using $wlan_ip on $WLAN_IF."
      prompt_yn "Proceed with configuration despite warnings? (y/n): " y || { log_info "Aborting."; return; }
    fi

    # Apply per-interface using responsible manager
    local NM_ACTIVE=0; systemctl is-active --quiet NetworkManager 2>/dev/null && NM_ACTIVE=1

    if [ $NM_ACTIVE -eq 1 ] && iface_managed_by_nm "$ETH_IF"; then
      apply_static_nm "$ETH_IF" "$ip_cidr" "$gateway" "$dns_norm"
    else
      apply_static_dhcpcd "$ETH_IF" "$ip_cidr" "$gateway" "$dns_norm"
    fi

    if [ $NM_ACTIVE -eq 1 ] && iface_managed_by_nm "$WLAN_IF"; then
      # Only modify if an NM Wi-Fi connection exists (don’t create placeholder)
      local cname; cname="$(nm_conn_for_iface "$WLAN_IF")"
      if [ -n "$cname" ]; then
        apply_static_nm "$WLAN_IF" "$wlan_cidr" "$gateway" "$dns_norm"
      else
        log_warning "No existing NM Wi-Fi connection on $WLAN_IF; skipping static config for Wi-Fi. Add Wi-Fi, then re-run."
      fi
    else
      apply_static_dhcpcd "$WLAN_IF" "$wlan_cidr" "$gateway" "$dns_norm"
    fi

    log_info "Configured $ETH_IF:  ${ip_cidr}"
    log_info "Configured $WLAN_IF: ${wlan_cidr}"
    return
  fi

  # Single-interface flow
  local iface ip_cidr gateway dns dns_norm first_dns
  local prompt_default="${ETH_IF:-$default_iface}"
  iface=$(read_tty "Interface to configure [${prompt_default}]: " "${prompt_default}")
  iface_exists "$iface" || { log_error "Interface $iface not found"; return 1; }

  while true; do
    ip_cidr=$(read_tty "Static IP (CIDR, e.g. 192.168.1.50/24): " "")
    [ -z "$ip_cidr" ] && { log_warning "No IP provided, aborting"; return; }
    validate_cidr "$ip_cidr" && break || log_warning "Invalid CIDR. Try again."
  done
  while true; do
    gateway=$(read_tty "Gateway (e.g. 192.168.1.1): " "")
    [ -z "$gateway" ] && { log_warning "No gateway provided, aborting"; return; }
    validate_ip "$gateway" && break || log_warning "Invalid IP. Try again."
  done
  while true; do
    dns=$(read_tty "DNS servers (comma/space separated, default: ${gateway}): " "${gateway}")
    dns_norm="$(normalize_dns "$dns")"
    first_dns="$(echo "$dns_norm" | awk '{print $1}')"
    validate_ip "$first_dns" && break || log_warning "Invalid DNS. Try again."
  done

  local NM_ACTIVE=0; systemctl is-active --quiet NetworkManager 2>/dev/null && NM_ACTIVE=1
  if [ $NM_ACTIVE -eq 1 ] && iface_managed_by_nm "$iface"; then
    # Only modify existing NM connection; don’t create placeholder Wi-Fi
    local cname; cname="$(nm_conn_for_iface "$iface")"
    if [ -n "$cname" ]; then
      apply_static_nm "$iface" "$ip_cidr" "$gateway" "$dns_norm"
    else
      log_warning "No NM connection for $iface; cannot set static via NM. Use dhcpcd or create a real NM connection first."
    fi
  else
    apply_static_dhcpcd "$iface" "$ip_cidr" "$gateway" "$dns_norm"
  fi
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
╔══════════════════════════════════════════════════════╗
║  MML Universal Raspberry Pi Setup Script             ║
║  Enhanced Security Edition                           ║
║  2025-10-24 e                                        ║
╚══════════════════════════════════════════════════════╝
EOF
echo ""
log_info "Version: $SCRIPT_VERSION"
echo ""

[ "$DRY_RUN" -eq 1 ] && log_warning "DRY-RUN MODE: No changes will be made"

############################################################
# Recovery / Resume
############################################################
LAST_CHECKPOINT=$(load_checkpoint)

if [ "$LAST_CHECKPOINT" != "START" ] && [ "$LAST_CHECKPOINT" != "COMPLETE" ] && [ "$FORCE_RERUN" -eq 0 ]; then
  log_warning "Previous installation interrupted at: $LAST_CHECKPOINT"
  if prompt_yn "Resume from last checkpoint? (y/n): " y; then
    log_info "Resuming from: $LAST_CHECKPOINT"
  else
    clear_checkpoint
    LAST_CHECKPOINT="START"
  fi
else
  LAST_CHECKPOINT="START"
fi

if load_state && [ "$FORCE_RERUN" -eq 0 ] && [ "$LAST_CHECKPOINT" = "COMPLETE" ]; then
  log_info "Previous installation detected"
  log_info "Use --force to rerun"
  exit 0
fi

############################################################
# Locale
############################################################
if ! is_checkpoint_passed "LOCALE"; then
  setup_locale || exit 1
  save_checkpoint "LOCALE"
fi

############################################################
# Detection
############################################################
if ! is_checkpoint_passed "DETECT"; then
  detect_pi_info
  select_pi_model
  select_profile
  save_checkpoint "DETECT"
fi

############################################################
# Hostname
############################################################
if ! is_checkpoint_passed "HOSTNAME"; then
  set_hostname
  save_checkpoint "HOSTNAME"
fi

############################################################
# Network (UPDATED)
############################################################
if ! is_checkpoint_passed "NETWORK"; then
  configure_network
  save_checkpoint "NETWORK"
fi

############################################################
# Swap
############################################################
if ! is_checkpoint_passed "SWAP"; then
  [[ "$PERF_TIER" == "LOW" || "$PERF_TIER" == "MINIMAL" ]] && setup_swap
  save_checkpoint "SWAP"
fi

############################################################
# System Update
############################################################
if ! is_checkpoint_passed "UPDATE"; then
  log_info "Updating package lists..."
  if [ "$DRY_RUN" -eq 0 ]; then
    sudo apt-get update -y || exit 1
  fi
  save_checkpoint "UPDATE"
fi

############################################################
# System Upgrade
############################################################
if ! is_checkpoint_passed "UPGRADE"; then
  if [[ "$PERF_TIER" == "MINIMAL" ]]; then
    if prompt_yn "Proceed with system upgrade? (slow) (y/n): " y; then
      log_info "Upgrading packages..."
      if [ "$DRY_RUN" -eq 0 ]; then
        sudo apt-get upgrade -y &
        show_progress $! "Upgrading packages"
      fi
    fi
  else
    log_info "Upgrading packages..."
    if [ "$DRY_RUN" -eq 0 ]; then
      if [[ "$PERF_TIER" == "LOW" ]]; then
        sudo apt-get upgrade -y &
        show_progress $! "Upgrading packages"
      else
        sudo apt-get upgrade -y
      fi
    fi
  fi
  save_checkpoint "UPGRADE"
  check_temperature
fi

############################################################
# Essential Packages
############################################################
if ! is_checkpoint_passed "ESSENTIAL"; then
  log_info "Installing essential packages..."
  ESSENTIAL_PACKAGES=(
    curl wget git vim htop tree unzip
    apt-transport-https ca-certificates gnupg
    lsb-release net-tools ufw arping
  )
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
      if prompt_yn "Install Node.js? (y/n): " n; then
        ESSENTIAL_PACKAGES+=(nodejs npm)
      fi
    fi
  fi
  install_packages "${ESSENTIAL_PACKAGES[@]}" || exit 1
  save_checkpoint "ESSENTIAL"
  check_temperature
fi
# ... (In your Essential Packages section): ...

log_info "Checking fastfetch installation..."

if ! command -v fastfetch >/dev/null 2>&1; then
  log_info "Trying to install fastfetch with apt-get first..."
  if sudo apt-get update -y && sudo apt-get install -y fastfetch; then
    if command -v fastfetch >/dev/null 2>&1; then
      log_success "fastfetch installed via apt-get"
    else
      log_warning "apt-get install completed, but fastfetch command not found. Trying fallback methods..."
    fi
  else
    log_warning "apt-get install fastfetch failed or package not found. Trying fallback methods..."
  fi

  if ! command -v fastfetch >/dev/null 2>&1; then
    log_info "Attempting to install fastfetch from GitHub releases..."
    FF_TEMP="$(mktemp -d)"
    FF_VERSION="$(curl -fsSL https://api.github.com/repos/fastfetch-cli/fastfetch/releases/latest | grep tag_name | cut -d '"' -f4)"
    FF_UNAME="$(uname -m)"
    FF_ARCHIVE=""
    FF_URL=""

    case "$FF_UNAME" in
      armv6l)
        log_info "Detected Pi 1/Zero (armv6l)"
        FF_ARCHIVE="fastfetch-linux-armv6l.tar.gz"
        ;;
      armv7l)
        log_info "Detected Pi 2/3 (armv7l)"
        FF_ARCHIVE="fastfetch-linux-armv7l.tar.gz"
        ;;
      aarch64|arm64)
        log_info "Detected Pi 3/4/5 64-bit (aarch64)"
        FF_ARCHIVE="fastfetch-linux-aarch64.tar.gz"
        ;;
      x86_64)
        log_info "Detected x86_64 (not a Raspberry Pi)"
        FF_ARCHIVE="fastfetch-linux-amd64.tar.gz"
        ;;
      *)
        log_warning "Unknown architecture ($FF_UNAME), defaulting to armv7l. If Pi 1/Zero, try 'armv6l'."
        FF_ARCHIVE="fastfetch-linux-armv7l.tar.gz"
        ;;
    esac

    FF_URL="https://github.com/fastfetch-cli/fastfetch/releases/download/${FF_VERSION}/${FF_ARCHIVE}"
    log_info "Attempting download: $FF_URL"

    if curl -fsSL "$FF_URL" -o "$FF_TEMP/$FF_ARCHIVE" && tar -xzf "$FF_TEMP/$FF_ARCHIVE" -C "$FF_TEMP" && [ -x "$FF_TEMP/fastfetch" ]; then
      sudo install -m 755 "$FF_TEMP/fastfetch" /usr/local/bin/fastfetch
      if command -v fastfetch >/dev/null 2>&1; then
        log_success "fastfetch installed from GitHub release (${FF_ARCHIVE})"
      else
        log_error "Download and extraction worked, but fastfetch not on path. Check /usr/local/bin or install manually."
      fi
    else
      log_error "GitHub release binary download failed or not compatible. Trying to build from source with cargo..."
      if command -v cargo >/dev/null 2>&1; then
        if cargo install fastfetch; then
          log_success "fastfetch installed with cargo"
        else
          log_error "Failed to build fastfetch from source with cargo. See https://github.com/fastfetch-cli/fastfetch"
        fi
      else
        log_error "Cargo (Rust) not available. Please install cargo/rust or download binaries manually."
      fi
    fi

    rm -rf "$FF_TEMP"
  fi

else
  log_success "fastfetch already installed."
fi

############################################################
# Security
############################################################
if ! is_checkpoint_passed "SECURITY"; then
  log_info "Setting up firewall..."
  if [ "$DRY_RUN" -eq 0 ]; then
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow ssh comment 'SSH'
    sudo ufw --force enable
    log_success "Firewall configured"
  fi
  if ! systemctl is-active --quiet ssh 2>/dev/null; then
    if [ "$DRY_RUN" -eq 0 ]; then
      sudo systemctl enable --now ssh
    fi
  fi
  save_checkpoint "SECURITY"
fi

############################################################
# VNC
############################################################
if ! is_checkpoint_passed "VNC"; then
  if [ "$ENABLE_VNC" -eq 1 ] || prompt_yn "Enable VNC? (y/n): " n; then
    setup_vnc
  else
    VNC_ENABLED=0
  fi
  save_checkpoint "VNC"
fi

############################################################
# Git
############################################################
if ! is_checkpoint_passed "GIT"; then
  if prompt_yn "Configure Git? (y/n): " n; then
    git_username=""
    git_email=""

    git_username=$(read_tty "Git username: " "")
    git_email=$(read_tty "Git email: " "")

    if [ -n "$git_username" ] && [ -n "$git_email" ]; then
      if validate_email "$git_email"; then
        if [ "$DRY_RUN" -eq 0 ]; then
          git config --global user.name "$git_username"
          git config --global user.email "$git_email"
          git config --global init.defaultBranch main
          git config --global pull.rebase false
          log_success "Git configured"
        fi
      fi
    fi
  fi
  save_checkpoint "GIT"
fi

############################################################
# Email (UPDATED: msmtp with secure file, no GPG)
############################################################
if ! is_checkpoint_passed "EMAIL"; then
  if [ ! -f ~/.msmtprc ]; then
    if prompt_yn "Configure email (msmtp for Gmail)? (y/n): " n; then
      install_packages msmtp msmtp-mta gpg

      mkdir -p ~/.secrets
      chmod 700 ~/.secrets

      email_address=""
      email_address=$(read_tty "Gmail address: " "")

      if [ -n "$email_address" ] && validate_email "$email_address"; then
        log_info "Create an App Password at: https://myaccount.google.com/apppasswords"
        app_password=""
        app_password=$(read_secure "Gmail App Password (16 chars, no spaces): ")
        app_password="$(echo "$app_password" | tr -d ' ')"

        if [ -n "$app_password" ] && [ ${#app_password} -eq 16 ]; then
          if [ "$DRY_RUN" -eq 0 ]; then
            # Store password in a 600 file and reference via passwordeval
            echo "$app_password" > ~/.secrets/msmtp.pass
            chmod 600 ~/.secrets/msmtp.pass
            unset app_password

            cat > ~/.msmtprc <<'MSMTPEOF'
defaults
auth           on
tls            on
tls_starttls   on
tls_trust_file /etc/ssl/certs/ca-certificates.crt
logfile        ~/.msmtp.log

account        gmail
host           smtp.gmail.com
port           587
from           EMAIL_PLACEHOLDER
user           EMAIL_PLACEHOLDER
passwordeval   "cat ~/.secrets/msmtp.pass"

account default : gmail
MSMTPEOF

            sed -i "s/EMAIL_PLACEHOLDER/$email_address/g" ~/.msmtprc
            chmod 600 ~/.msmtprc

            : > ~/.msmtp.log
            chmod 600 ~/.msmtp.log

            log_info "Testing email..."
            if echo "Test from $(hostname)" | msmtp "$email_address" 2>/dev/null; then
              log_success "Email configured and tested"
            else
              log_warning "Email configured but test failed (check ~/.msmtp.log)"
            fi
          fi
        else
          log_error "Invalid app password length."
        fi
      else
        log_warning "Invalid email; skipping msmtp setup."
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
    log_info "Configuring Pi-specific settings..."
    if [ "$DRY_RUN" -eq 0 ]; then
      sudo raspi-config nonint do_expand_rootfs || true
    fi
    if prompt_yn "Enable I2C? (y/n): " n; then
      [ "$DRY_RUN" -eq 0 ] && sudo raspi-config nonint do_i2c 0
    fi
    if prompt_yn "Enable SPI? (y/n): " n; then
      [ "$DRY_RUN" -eq 0 ] && sudo raspi-config nonint do_spi 0
    fi
    if prompt_yn "Enable Camera? (y/n): " n; then
      [ "$DRY_RUN" -eq 0 ] && sudo raspi-config nonint do_camera 0
    fi
  fi
  save_checkpoint "RASPI_CONFIG"
fi

############################################################
# Python
############################################################
if ! is_checkpoint_passed "PYTHON"; then
  if [[ "$PERF_TIER" != "MINIMAL" ]]; then
    setup_piwheels
    if prompt_yn "Install Python packages? (y/n): " y; then
      PYTHON_PACKAGES=()
      if [[ "$PERF_TIER" == "LOW" ]]; then
        PYTHON_PACKAGES+=(requests RPi.GPIO)
        prompt_yn "Install Flask? (y/n): " n && PYTHON_PACKAGES+=(flask)
      elif [[ "$PERF_TIER" == "MEDIUM" ]]; then
        PYTHON_PACKAGES+=(requests flask RPi.GPIO)
        prompt_yn "Install numpy? (y/n): " n && PYTHON_PACKAGES+=(numpy)
      else
        PYTHON_PACKAGES+=(numpy requests flask RPi.GPIO)
      fi
      if [ ${#PYTHON_PACKAGES[@]} -gt 0 ]; then
        if [ "$DRY_RUN" -eq 0 ]; then
          pip3 install --user --no-warn-script-location "${PYTHON_PACKAGES[@]}" || log_warning "Some packages failed"
          if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
          fi
        fi
      fi
    fi
  fi
  save_checkpoint "PYTHON"
  check_temperature
fi

############################################################
# Profile
############################################################
if ! is_checkpoint_passed "PROFILE"; then
  log_info "Installing profile: $PROFILE"
  case $PROFILE in
    web)
      if [[ "$PERF_TIER" == "MINIMAL" ]]; then
        if prompt_yn "Web profile on MINIMAL tier? (y/n): " n; then
          install_packages nginx php-fpm sqlite3 php-sqlite3
          [ "$DRY_RUN" -eq 0 ] && sudo systemctl enable --now nginx
        fi
      else
        install_packages nginx php-fpm mariadb-server php-mysql
        if [ "$DRY_RUN" -eq 0 ]; then
          sudo systemctl enable --now nginx mariadb
          sudo ufw allow 'Nginx HTTP'
        fi
      fi
      ;;
    iot)
      install_packages mosquitto mosquitto-clients
      if [ "$DRY_RUN" -eq 0 ]; then
        [[ "$PERF_TIER" != "MINIMAL" ]] && pip3 install --user paho-mqtt adafruit-blinka
        sudo systemctl enable --now mosquitto
        sudo ufw allow 1883 comment 'MQTT'
      fi
      ;;
    media)
      if [[ "$PERF_TIER" == "MINIMAL" ]]; then
        install_packages omxplayer
      else
        install_packages vlc mpv ffmpeg
      fi
      ;;
    dev)
      DEV_PACKAGES=(tmux screen)
      [[ "$PERF_TIER" != "MINIMAL" ]] && DEV_PACKAGES+=(docker.io docker-compose)
      install_packages "${DEV_PACKAGES[@]}"
      if [ "$DRY_RUN" -eq 0 ] && command -v docker &>/dev/null; then
        sudo usermod -aG docker "$USER"
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
# Aliases
############################################################
if ! is_checkpoint_passed "ALIASES"; then
  log_info "Creating directories and aliases..."
  if [ "$DRY_RUN" -eq 0 ]; then
    mkdir -p ~/projects ~/scripts ~/backup ~/logs
    if ! grep -q "# === Custom Aliases ===" ~/.bashrc; then
      cat >> ~/.bashrc <<'BASHEOF'

# === Custom Aliases ===
alias ll='ls -alF'
alias la='ls -A'
alias ..='cd ..'
alias temp='vcgencmd measure_temp'
alias memory='free -h'
alias disk='df -h'
alias update='sudo apt update && sudo apt upgrade -y'
alias sysinfo='~/scripts/sysinfo.sh'
alias profile='cat ~/.rpi_setup_state'

BASHEOF
    fi

    cat > ~/scripts/sysinfo.sh <<'SYSINFOEOF'
#!/bin/bash
echo "=========================================="
echo "Raspberry Pi System Information"
echo "=========================================="
echo "Hostname:    $(hostname)"
echo "Model:       $(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')"
echo "OS:          $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "Uptime:      $(uptime -p)"
echo "Temperature: $(vcgencmd measure_temp 2>/dev/null)"
echo "Memory:      $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "Disk:        $(df -h / | awk '/\// {print $3 "/" $2}')"
echo "IP:          $(hostname -I | awk '{print $1}')"
[ -f ~/.rpi_setup_state ] && echo "Profile:     $(grep PROFILE= ~/.rpi_setup_state | cut -d= -f2)"
echo "=========================================="
SYSINFOEOF
    chmod +x ~/scripts/sysinfo.sh
  fi
  save_checkpoint "ALIASES"
fi

############################################################
# Finalize
############################################################
save_state

if [ "$DRY_RUN" -eq 0 ]; then
  log_info "Cleaning up..."
  sudo apt-get autoremove -y
  sudo apt-get autoclean
fi

save_checkpoint "COMPLETE"
clear_checkpoint

############################################################
# Summary
############################################################
echo ""
echo "=========================================="
log_success "Setup completed successfully!"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  Hostname: ${NEW_HOSTNAME:-$(hostname)}"
echo "  Model: Pi $PI_MODEL"
echo "  Memory: ${PI_MEMORY}MB"
echo "  Tier: $PERF_TIER"
echo "  Profile: $PROFILE"
echo "  VNC: $([ "${VNC_ENABLED:-0}" -eq 1 ] && echo 'Enabled (port 5900)' || echo 'Disabled')"
echo ""
echo "Commands:"
echo "  sysinfo  - System information"
echo "  temp     - CPU temperature"
echo "  update   - Update packages"
echo ""

if [ "${VNC_ENABLED:-0}" -eq 1 ]; then
  vnc_ip=$(hostname -I | awk '{print $1}')
  echo "VNC Connection:"
  echo "  Address: ${vnc_ip}:5900"
  echo "  or: ${NEW_HOSTNAME:-$(hostname)}.local:5900"
  echo ""
fi

log_warning "Reboot required to finalize all changes!"
echo ""

if [ "$DRY_RUN" -eq 1 ]; then
  log_info "DRY-RUN complete - no changes made"
  exit 0
fi

if prompt_yn "Reboot now? (y/n): " n; then
  log_info "Rebooting in 5 seconds... (Ctrl+C to cancel)"
  sleep 5
  sudo reboot
else
  log_info "Remember to reboot when convenient: sudo reboot"
  log_success "Setup complete! Enjoy your Raspberry Pi!"
fi
