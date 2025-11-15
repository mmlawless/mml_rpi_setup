#!/bin/bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

############################################################
# Function definitions (all at top for pipe-to-bash)
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

install_packages() {
  local package_list=("$@")
  [ ${#package_list[@]} -eq 0 ] && return 0

  log_info "Installing: ${package_list[*]}"
  [ "${DRY_RUN:-0}" -eq 1 ] && return 0

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

prompt_feature_toggle() {
  local feature="$1"
  local state="$2"
  local enable_cmd="$3"
  local disable_cmd="$4"
  echo ""
  echo "$feature is currently $state."
  echo "Choose:"
  echo "  [e]nable"
  echo "  [d]isable"
  echo "  [l]eave as-is (default)"
  read -r -p "Select action [l]: " action
  action="${action,,}" # lowercase
  case "$action" in
    e)
      log_info "Enabling $feature..."
      eval "$enable_cmd"
      ;;
    d)
      log_info "Disabling $feature..."
      eval "$disable_cmd"
      ;;
    *)
      log_info "Leaving $feature as is."
      ;;
  esac
}

prompt_yn() {
  local question="$1" default="${2:-n}" ans
  read -r -p "$question " ans
  ans="${ans:-$default}"
  [[ "$ans" =~ ^[Yy]$ ]]
}

############################################################
# Script variables/state and header banner
############################################################

SCRIPT_VERSION="2025-11-14"
SCRIPT_HASH="PLACEHOLDER_HASH"
STATE_FILE="$HOME/.rpi_setup_state"
CHECKPOINT_FILE="$HOME/.rpi_setup_checkpoint"
LOG_FILE="$HOME/.rpi_setup.log"
LOCK_FILE="/tmp/rpi_setup.lock"
DRY_RUN=0

# Box banner for setup script/version
clear
cat <<EOF
╔══════════════════════════════════════════════════════╗
║  MML Universal Raspberry Pi Setup Script             ║
║  Enhanced Security Edition                           ║
║  Version: $SCRIPT_VERSION$(printf "%*s" $((46 - ${#SCRIPT_VERSION} - 9)) "")║
╚══════════════════════════════════════════════════════╝
EOF
echo ""
log_info "Version: $SCRIPT_VERSION"
echo ""

############################################################
# Logging setup and lock
############################################################

setup_logging() {
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE")
  exec 2>&1
  log_info "=== Script started at $(date) ==="
  log_info "Version: $SCRIPT_VERSION"
}
setup_logging
# Acquire lock
if [ -e "$LOCK_FILE" ]; then
  log_error "Lock file exists, another instance is running."
  exit 1
fi
echo $$ > "$LOCK_FILE"
chmod 600 "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

############################################################
# Show completed checkpoints on startup
############################################################
ALL_CHECKPOINTS=(START LOCALE DETECT HOSTNAME NETWORK SWAP UPDATE UPGRADE ESSENTIAL SECURITY VNC GIT EMAIL RASPI_CONFIG PYTHON PROFILE ALIASES COMPLETE)
COMPLETED=""
CURRENT_RAW=$(load_checkpoint)

current_index=-1
for i in "${!ALL_CHECKPOINTS[@]}"; do
    if [[ "${ALL_CHECKPOINTS[$i]}" == "$CURRENT_RAW" ]]; then
        current_index=$i
        break
    fi
done

if [[ $current_index -ge 0 ]]; then
    for j in $(seq 0 $current_index); do
        COMPLETED="${COMPLETED}${ALL_CHECKPOINTS[$j]}, "
    done
    COMPLETED="${COMPLETED%, }"
else
    COMPLETED="None"
fi

echo ""
echo "=========================================="
echo "Completed Checkpoints (last complete: $CURRENT_RAW):"
echo "  $COMPLETED"
echo "=========================================="
echo ""

############################################################
# Feature sections with toggles (SPI, I2C, Camera, VNC, Firewall, Swap, Git, Python)
############################################################

# SPI
if ! is_checkpoint_passed "RASPI_CONFIG"; then
  SPI_STATE=$(grep -q '^dtparam=spi=on' /boot/config.txt && echo "enabled" || echo "disabled")
  prompt_feature_toggle "SPI" "$SPI_STATE" \
    "sudo raspi-config nonint do_spi 0" \
    "sudo raspi-config nonint do_spi 1"
  # I2C
  I2C_STATE=$(grep -q '^dtparam=i2c_arm=on' /boot/config.txt && echo "enabled" || echo "disabled")
  prompt_feature_toggle "I2C" "$I2C_STATE" \
    "sudo raspi-config nonint do_i2c 0" \
    "sudo raspi-config nonint do_i2c 1"
  # Camera
  CAMERA_STATE=$(vcgencmd get_camera 2>/dev/null | grep -q 'supported=1 detected=1' && echo "enabled" || echo "disabled")
  prompt_feature_toggle "Camera" "$CAMERA_STATE" \
    "sudo raspi-config nonint do_camera 0" \
    "sudo raspi-config nonint do_camera 1"
  save_checkpoint "RASPI_CONFIG"
fi

# VNC
if ! is_checkpoint_passed "VNC"; then
  VNC_SERVICE_STATUS=$(systemctl is-enabled vncserver-x11-serviced.service 2>/dev/null | grep -q enabled && echo "enabled" || echo "disabled")
  prompt_feature_toggle "VNC" "$VNC_SERVICE_STATUS" \
    "sudo systemctl enable --now vncserver-x11-serviced.service" \
    "sudo systemctl disable --now vncserver-x11-serviced.service"
  save_checkpoint "VNC"
fi

# Firewall(UFW)
if ! is_checkpoint_passed "SECURITY"; then
  UFW_STATUS=$(sudo ufw status | grep -qw "active" && echo "enabled" || echo "disabled")
  prompt_feature_toggle "Firewall (UFW)" "$UFW_STATUS" \
    "sudo ufw --force enable" \
    "sudo ufw disable"
  save_checkpoint "SECURITY"
fi

# SWAP
if ! is_checkpoint_passed "SWAP"; then
  CURRENT_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
  SWAP_STATE=$([ "$CURRENT_SWAP" -ge 1024 ] && echo "enabled" || echo "disabled")
  prompt_feature_toggle "1024MB Swap" "$SWAP_STATE" \
    "sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile; sudo dphys-swapfile setup; sudo dphys-swapfile swapon" \
    "sudo dphys-swapfile swapoff; sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=100/' /etc/dphys-swapfile; sudo dphys-swapfile setup; sudo dphys-swapfile swapon"
  save_checkpoint "SWAP"
fi

# Git config
if ! is_checkpoint_passed "GIT"; then
  GIT_NAME="$(git config --global user.name 2>/dev/null || true)"
  GIT_EMAIL="$(git config --global user.email 2>/dev/null || true)"
  if [[ -n "$GIT_NAME" && -n "$GIT_EMAIL" ]]; then
    echo "Git is already configured: $GIT_NAME <$GIT_EMAIL>"
    echo "Options:"
    echo "  [r]econfigure"
    echo "  [l]eave (default)"
    read -r -p "Select action [l]: " menu
    menu="${menu,,}"
    if [[ "$menu" == "r" ]]; then
      read -r -p "Git username: " git_username
      read -r -p "Git email: " git_email
      [ -n "$git_username" ] && [ -n "$git_email" ] && git config --global user.name "$git_username" && git config --global user.email "$git_email"
      log_success "Git reconfigured"
    else
      log_info "Leaving git config unchanged."
    fi
  else
    read -r -p "Git username: " git_username
    read -r -p "Git email: " git_email
    [ -n "$git_username" ] && [ -n "$git_email" ] && git config --global user.name "$git_username" && git config --global user.email "$git_email"
    log_success "Git configured"
  fi
  save_checkpoint "GIT"
fi

# Python packages
if ! is_checkpoint_passed "PYTHON"; then
  PYTHON_PKGS_INSTALLED=$(pip3 list | grep -qw requests && echo "installed" || echo "not installed")
  prompt_feature_toggle "requests (Python package)" "$PYTHON_PKGS_INSTALLED" \
    "pip3 install --user --upgrade requests" \
    "pip3 uninstall -y requests"
  save_checkpoint "PYTHON"
fi

# Neofetch install and auto-run in terminal.
if ! command -v neofetch >/dev/null 2>&1; then
  install_packages neofetch
fi
if ! grep -qx "neofetch" ~/.bashrc; then
  echo "neofetch" >> ~/.bashrc
  log_info "Configured neofetch to run on new terminal (added to ~/.bashrc)"
else
  log_info "neofetch already configured to run on new terminal in ~/.bashrc"
fi

# Aliases (not toggle)
if ! is_checkpoint_passed "ALIASES"; then
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
  save_checkpoint "ALIASES"
fi

############################################################
# Always set state variables for summary reporting
############################################################

CURRENT_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
SWAP_STATE=$([ "$CURRENT_SWAP" -ge 1024 ] && echo "enabled" || echo "disabled")
VNC_SERVICE_STATUS=$(systemctl is-enabled vncserver-x11-serviced.service 2>/dev/null | grep -q enabled && echo "enabled" || echo "disabled")
UFW_STATUS=$(sudo ufw status | grep -qw "active" && echo "enabled" || echo "disabled")
SPI_STATE=$(grep -q '^dtparam=spi=on' /boot/config.txt && echo "enabled" || echo "disabled")
I2C_STATE=$(grep -q '^dtparam=i2c_arm=on' /boot/config.txt && echo "enabled" || echo "disabled")
CAMERA_STATE=$(vcgencmd get_camera 2>/dev/null | grep -q 'supported=1 detected=1' && echo "enabled" || echo "disabled")
GIT_NAME="$(git config --global user.name 2>/dev/null || echo "not set")"
GIT_EMAIL="$(git config --global user.email 2>/dev/null || echo "not set")"
PYTHON_PKGS_INSTALLED=$(pip3 list | grep -qw requests && echo "installed" || echo "not installed")

############################################################
# Finish script as usual (summary, reboot prompt...)
############################################################

echo ""
echo "=========================================="
log_success "Setup completed successfully!"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  Swap: $SWAP_STATE"
echo "  SPI: $SPI_STATE"
echo "  I2C: $I2C_STATE"
echo "  Camera: $CAMERA_STATE"
echo "  VNC: $VNC_SERVICE_STATUS"
echo "  Firewall (UFW): $UFW_STATUS"
echo "  Git: $GIT_NAME <$GIT_EMAIL>"
echo "  Python requests: $PYTHON_PKGS_INSTALLED"
echo ""
log_warning "Reboot required to finalize all changes!"
echo ""
if prompt_yn "Reboot now? (y/n): " n; then
  log_info "Rebooting in 5 seconds... (Ctrl+C to cancel)"
  sleep 5
  sudo reboot
else
  log_info "Remember to reboot when convenient: sudo reboot"
  log_success "Setup complete! Enjoy your Raspberry Pi!"
fi
