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

trap '' PIPE

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

run_neofetch_if_installed() {
  if command -v neofetch >/dev/null 2>&1; then neofetch; fi
}

############################################################
# Script variables/state and header banner
############################################################

SCRIPT_VERSION="2025-11-15ff"
SCRIPT_HASH="PLACEHOLDER_HASH"
STATE_FILE="$HOME/.rpi_setup_state"
CHECKPOINT_FILE="$HOME/.rpi_setup_checkpoint"
LOG_FILE="$HOME/.rpi_setup.log"
LOCK_FILE="/tmp/rpi_setup.lock"
DRY_RUN=0

# Banner
clear
cat <<EOF
╔══════════════════════════════════════════════════════╗
║  MML Universal Raspberry Pi Setup Script             ║
║  Enhanced Security Edition                           ║
║  Version: $SCRIPT_VERSION$(printf "%*s" $((46 - ${#SCRIPT_VERSION} - 9)) "")║
╚══════════════════════════════════════════════════════╝
EOF

run_neofetch_if_installed

echo ""
log_info "Version: $SCRIPT_VERSION"
echo ""

setup_logging() {
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE"
  exec > >(tee -a "$LOG_FILE")
  exec 2>&1
  log_info "=== Script started at $(date) ==="
  log_info "Version: $SCRIPT_VERSION"
}
setup_logging
if [ -e "$LOCK_FILE" ]; then
  log_error "Lock file exists, another instance is running."
  exit 1
fi
echo $$ > "$LOCK_FILE"
chmod 600 "$LOCK_FILE"
trap 'rm -f "$LOCK_FILE"' EXIT

############################################################
# Checkpoint names and complete checkpoint reporting
############################################################
CHECKPOINTS=(START LOCALE DETECT HOSTNAME NETWORK SWAP UPDATE UPGRADE ESSENTIAL SECURITY VNC GIT EMAIL RASPI_CONFIG PYTHON PROFILE ALIASES COMPLETE)
checkpoint_menu=("${CHECKPOINTS[@]}")

get_completed_checkpoints() {
  local last=$(load_checkpoint)
  local last_index=-1
  for i in "${!CHECKPOINTS[@]}"; do
    if [[ "${CHECKPOINTS[$i]}" == "$last" ]]; then
      last_index=$i
      break
    fi
  done
  local completed=()
  if [[ $last_index -ge 0 ]]; then
    for c in $(seq 0 $last_index); do completed+=("${CHECKPOINTS[$c]}"); done
  fi
  echo "${completed[*]}"
}
echo ""
echo "=========================================="
completed=$(get_completed_checkpoints)
echo "Completed Checkpoints (last complete: $(load_checkpoint)):"
echo "  ${completed:-None}"
echo "=========================================="
echo ""

############################################################
# Interactive checkpoint menu for selecting actions
############################################################
choose_checkpoint() {
  echo "Select a checkpoint/process to run:"
  for i in "${!checkpoint_menu[@]}"; do
    printf "  %2d) %s\n" $((i+1)) "${checkpoint_menu[$i]}"
  done
  echo ""
  echo "Or enter blank to run all from the next incomplete."
  read -r -p "Enter checkpoint number or blank [all]: " choice
  if [[ -z "$choice" ]]; then
    echo "ALL"
    return
  fi
  # Validate
  if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 )) && (( choice <= ${#checkpoint_menu[@]} )); then
    echo "${checkpoint_menu[$((choice-1))]}"
    return
  fi
  echo "ALL"
}

############################################################
# Individual checkpoint logic as separate functions
############################################################

run_START() {
  log_info "START: Script initialized."
  save_checkpoint "START"
}

run_LOCALE() {
  log_info "Setting up locale (en_GB.UTF-8)..."
  sudo apt-get install -y locales
  sudo locale-gen en_GB.UTF-8
  sudo update-locale LANG=en_GB.UTF-8
  log_success "Locale configured successfully"
  save_checkpoint "LOCALE"
}

run_DETECT() {
  log_info "Detecting hardware..."
  log_success "Hardware detection is complete"
  save_checkpoint "DETECT"
}

run_HOSTNAME() {
  local generated="LH-PI-NEW"
  local current_hostname=$(hostname)
  local input
  read -r -p "Enter desired hostname (leave blank for auto): " input
  local new_hostname="$current_hostname"
  if [ -n "$input" ]; then
    if validate_hostname "$input"; then
      new_hostname="$input"
    else
      log_warning "Invalid hostname. Using auto-detected."
      new_hostname="$generated"
    fi
  else
    new_hostname="$generated"
  fi
  log_info "Setting hostname to $new_hostname"
  echo "$new_hostname" | sudo tee /etc/hostname >/dev/null
  sudo hostnamectl set-hostname "$new_hostname"
  log_success "Hostname set"
  save_checkpoint "HOSTNAME"
}

run_NETWORK() {
  local iface
  read -r -p "Configure static network interface? (enter iface, blank=skip): " iface
  if [[ -n "$iface" ]]; then
    local ip gw
    read -r -p "Enter static IP (CIDR, e.g. 192.168.1.50/24): " ip
    read -r -p "Enter gateway/router (e.g. 192.168.1.1): " gw
    if validate_cidr "$ip" && validate_ip "$gw"; then
      sudo sed -i '/interface '"$iface"'/,/^$/d' /etc/dhcpcd.conf
      echo -e "interface $iface\nstatic ip_address=$ip\nstatic routers=$gw\n" | sudo tee -a /etc/dhcpcd.conf
      sudo systemctl restart dhcpcd || true
      log_success "Static IP configured"
    else
      log_error "Invalid IP or gateway format."
    fi
  else
    log_info "Network config skipped"
  fi
  save_checkpoint "NETWORK"
}

run_SWAP() {
  local current_swap=$(free -m | awk '/^Swap:/ {print $2}')
  local state=$([ "$current_swap" -ge 1024 ] && echo "enabled" || echo "disabled")
  prompt_feature_toggle "1024MB Swap" "$state" \
    "sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile; sudo dphys-swapfile setup; sudo dphys-swapfile swapon" \
    "sudo dphys-swapfile swapoff; sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=100/' /etc/dphys-swapfile; sudo dphys-swapfile setup; sudo dphys-swapfile swapon"
  save_checkpoint "SWAP"
}

run_UPDATE() {
  log_info "Updating package lists..."
  sudo apt-get update -y
  log_success "Packages updated."
  save_checkpoint "UPDATE"
}

run_UPGRADE() {
  log_info "Upgrading system packages..."
  sudo apt-get upgrade -y
  log_success "Packages upgraded."
  save_checkpoint "UPGRADE"
}

run_ESSENTIAL() {
  local packages=(curl wget git vim htop tree unzip apt-transport-https ca-certificates gnupg lsb-release net-tools ufw arping neofetch)
  log_info "Installing essential packages..."
  install_packages "${packages[@]}"
  log_success "Essential packages installed."
  save_checkpoint "ESSENTIAL"
}

run_SECURITY() {
  local ufw_status=$(sudo ufw status | grep -qw "active" && echo "enabled" || echo "disabled")
  prompt_feature_toggle "Firewall (UFW)" "$ufw_status" \
    "sudo ufw --force enable" \
    "sudo ufw disable"
  save_checkpoint "SECURITY"
}

run_VNC() {
  local vnc_status=$(systemctl is-enabled vncserver-x11-serviced.service 2>/dev/null | grep -q enabled && echo "enabled" || echo "disabled")
  prompt_feature_toggle "VNC" "$vnc_status" \
    "sudo systemctl enable --now vncserver-x11-serviced.service" \
    "sudo systemctl disable --now vncserver-x11-serviced.service"
  save_checkpoint "VNC"
}

run_GIT() {
  local git_name="$(git config --global user.name 2>/dev/null || true)"
  local git_email="$(git config --global user.email 2>/dev/null || true)"
  if [[ -n "$git_name" && -n "$git_email" ]]; then
    echo "Git is already configured: $git_name <$git_email>"
    read -r -p "Reconfigure git? (y/n) [n]: " ans
    if [[ "${ans,,}" == "y" ]]; then
      git_name=""; git_email=""
    fi
  fi
  if [[ -z "$git_name" ]]; then
    read -r -p "Git username: " git_name
    git config --global user.name "$git_name"
  fi
  if [[ -z "$git_email" ]]; then
    read -r -p "Git email: " git_email
    git config --global user.email "$git_email"
  fi
  log_success "Git configured as $git_name <$git_email>"
  save_checkpoint "GIT"
}

run_EMAIL() {
  read -r -p "Configure email (for msmtp)? (y/n) [n]: " ans
  if [[ "${ans,,}" == "y" ]]; then
    echo "Please enter Gmail address: "
    read -r email_address
    echo "Create a Gmail App Password at: https://myaccount.google.com/apppasswords"
    read -rs -p "Gmail App Password: " app_pass
    echo ""
    install_packages msmtp msmtp-mta
    echo "$app_pass" > ~/.secrets_msmtp_pass
    chmod 600 ~/.secrets_msmtp_pass
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
passwordeval   "cat ~/.secrets_msmtp_pass"
account default : gmail
EOF
    chmod 600 ~/.msmtprc
    log_success "msmtp email configured!"
  else
    log_info "Skipped msmtp email setup."
  fi
  save_checkpoint "EMAIL"
}

run_RASPI_CONFIG() {
  SPI_STATE=$(grep -q '^dtparam=spi=on' /boot/config.txt && echo "enabled" || echo "disabled")
  prompt_feature_toggle "SPI" "$SPI_STATE" \
    "sudo raspi-config nonint do_spi 0" \
    "sudo raspi-config nonint do_spi 1"
  I2C_STATE=$(grep -q '^dtparam=i2c_arm=on' /boot/config.txt && echo "enabled" || echo "disabled")
  prompt_feature_toggle "I2C" "$I2C_STATE" \
    "sudo raspi-config nonint do_i2c 0" \
    "sudo raspi-config nonint do_i2c 1"
  CAMERA_STATE=$(vcgencmd get_camera 2>/dev/null | grep -q 'supported=1 detected=1' && echo "enabled" || echo "disabled")
  prompt_feature_toggle "Camera" "$CAMERA_STATE" \
    "sudo raspi-config nonint do_camera 0" \
    "sudo raspi-config nonint do_camera 1"
  save_checkpoint "RASPI_CONFIG"
}

run_PYTHON() {
  local py_pkg_state=$(pip3 list | grep -qw requests && echo "installed" || echo "not installed")
  prompt_feature_toggle "requests (Python package)" "$py_pkg_state" \
    "pip3 install --user --upgrade requests" \
    "pip3 uninstall -y requests"
  save_checkpoint "PYTHON"
}

run_PROFILE() {
  local profiles=("generic" "web" "iot" "media" "dev")
  echo "Available profiles:"
  for i in "${!profiles[@]}"; do
    echo "  $((i+1))) ${profiles[$i]}"
  done
  read -r -p "Select profile number [1]: " profnum
  profnum="${profnum:-1}"
  local profsel=${profiles[$((profnum-1))]}
  log_info "Profile selected: $profsel"
  save_checkpoint "PROFILE"
}

run_ALIASES() {
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
  log_success "Custom aliases and directories created"
  save_checkpoint "ALIASES"
}

run_COMPLETE() {
  save_checkpoint "COMPLETE"
}

############################################################
# Main process: menu-driven checkpoint selection loop
############################################################

function run_checkpoint_by_name() {
  local name="$1"
  case "$name" in
    START)          run_START ;;
    LOCALE)         run_LOCALE ;;
    DETECT)         run_DETECT ;;
    HOSTNAME)       run_HOSTNAME ;;
    NETWORK)        run_NETWORK ;;
    SWAP)           run_SWAP ;;
    UPDATE)         run_UPDATE ;;
    UPGRADE)        run_UPGRADE ;;
    ESSENTIAL)      run_ESSENTIAL ;;
    SECURITY)       run_SECURITY ;;
    VNC)            run_VNC ;;
    GIT)            run_GIT ;;
    EMAIL)          run_EMAIL ;;
    RASPI_CONFIG)   run_RASPI_CONFIG ;;
    PYTHON)         run_PYTHON ;;
    PROFILE)        run_PROFILE ;;
    ALIASES)        run_ALIASES ;;
    COMPLETE)       run_COMPLETE ;;
    *) log_warning "Unknown checkpoint $name";;
  esac
}

while true; do
  echo ""
  selection=$(choose_checkpoint)
  if [[ "$selection" == "ALL" ]]; then
    current=$(load_checkpoint)
    start_idx=0
    for i in "${!CHECKPOINTS[@]}"; do
      if [[ "${CHECKPOINTS[$i]}" == "$current" ]]; then
        start_idx=$((i+1))
        break
      fi
    done
    for ((i=start_idx; i<${#CHECKPOINTS[@]}; i++)); do
      run_checkpoint_by_name "${CHECKPOINTS[$i]}"
    done
    break
  else
    run_checkpoint_by_name "$selection"
    echo ""
    read -r -p "Return to menu? (y/n) [y]: " again
    [[ "${again,,}" == "n" ]] && break
  fi
done

############################################################
# Summary and reboot prompt
############################################################

# Set all states for summary
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

run_neofetch_if_installed

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
