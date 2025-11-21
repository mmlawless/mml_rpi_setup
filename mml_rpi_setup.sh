#!/bin/bash
# MML Universal Raspberry Pi Setup Script (simple + menu)
# Compatible with Legacy and Modern Raspberry Pi OS
# Single-file version intended for:
#   bash <(curl -sSL https://raw.githubusercontent.com/mmlawless/mml_rpi_setup/main/mml_rpi_setup_simple.sh) --force

trap '' PIPE

# Also handle it for any child processes
export PYTHONIOENCODING=utf-8
export PYTHONDONTWRITEBYTECODE=1

set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

# If the script is being piped (curl | bash), reattach stdin to the terminal
# so interactive prompts (read -r -p ...) still work correctly.
if [[ ! -t 0 ]] && [[ -e /dev/tty ]]; then
  exec < /dev/tty
fi

############################################################
# Colours & logging
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
log_debug()    { [ "${DEBUG:-0}" -eq 1 ] && echo -e "[DEBUG $(date +%H:%M:%S)] $1" || true; }

############################################################
# Argument parsing (e.g. --force)
############################################################

FORCE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --force)
      FORCE=1
      shift
      ;;
    *)
      log_warning "Unknown argument: $1"
      shift
      ;;
  esac
done

############################################################
# Detection & utilities
############################################################

detect_boot_config_path() {
  if [ -f "/boot/firmware/config.txt" ]; then
    echo "/boot/firmware/config.txt"
  elif [ -f "/boot/config.txt" ]; then
    echo "/boot/config.txt"
  else
    log_error "Cannot find boot config.txt"
    return 1
  fi
}

detect_boot_cmdline_path() {
  if [ -f "/boot/firmware/cmdline.txt" ]; then
    echo "/boot/firmware/cmdline.txt"
  elif [ -f "/boot/cmdline.txt" ]; then
    echo "/boot/cmdline.txt"
  else
    log_error "Cannot find boot cmdline.txt"
    return 1
  fi
}

detect_dhcpcd_config() {
  if systemctl is-active --quiet dhcpcd 2>/dev/null; then
    echo "dhcpcd"
  elif systemctl is-active --quiet NetworkManager 2>/dev/null; then
    echo "NetworkManager"
  else
    echo "unknown"
  fi
}

detect_os_version() {
  if [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    echo "$VERSION_CODENAME"
  else
    echo "unknown"
  fi
}

check_system_compatibility() {
  log_info "Checking system compatibility..."
  
  # Check if running on Raspberry Pi
  if [ ! -f /proc/device-tree/model ] && [ ! -f /etc/rpi-issue ]; then
    if [[ "$FORCE" -eq 1 ]]; then
      log_warning "This doesn't appear to be a Raspberry Pi, but --force is set. Continuing anyway."
    else
      log_warning "This doesn't appear to be a Raspberry Pi"
      read -r -p "Continue anyway? (y/n) [n]: " ans
      [[ "${ans,,}" != "y" ]] && exit 1
    fi
  fi
  
  # Check if running as root
  if [ "$EUID" -eq 0 ]; then
    log_error "Don't run as root. Run as normal user with sudo access."
    exit 1
  fi
  
  # Check sudo access
  if ! sudo -n true 2>/dev/null; then
    log_info "Testing sudo access..."
    if ! sudo true; then
      log_error "This script requires sudo access"
      exit 1
    fi
  fi
  
  # Detect system paths
  BOOT_CONFIG=$(detect_boot_config_path)
  BOOT_CMDLINE=$(detect_boot_cmdline_path)
  NETWORK_MANAGER=$(detect_dhcpcd_config)
  OS_VERSION=$(detect_os_version)
  
  log_success "System check passed"
  log_info "Boot config: $BOOT_CONFIG"
  log_info "Network manager: $NETWORK_MANAGER"
  log_info "OS version: $OS_VERSION"
}

install_packages() {
  local package_list=("$@")
  [ ${#package_list[@]} -eq 0 ] && return 0
  log_info "Installing: ${package_list[*]}"
  [ "${DRY_RUN:-0}" -eq 1 ] && return 0
  local max_retries=3
  local attempt=1
  while [ $attempt -le $max_retries ]; do
    if sudo apt-get install -y "${package_list[@]}" 2>&1; then
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

backup_config_file() {
  local file="$1"
  if [ -f "$file" ]; then
    local backup="${file}.backup.$(date +%Y%m%d_%H%M%S)"
    sudo cp "$file" "$backup"
    log_info "Backed up: $file -> $backup"
    return 0
  fi
  return 1
}

validate_hostname() {
  local hostname="$1"
  [[ "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$ ]] && [ ${#hostname} -le 63 ]
}

validate_ip() {
  local ip="$1"
  [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || return 1
  local IFS='.'
  # shellcheck disable=SC2206
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
  [[ "$prefix" =~ ^[0-9]+$ ]] && [ "$prefix" -ge 0 ] && [ "$prefix" -le 32 ]
}

get_pi_version() {
  local model

  if [ -f /proc/device-tree/model ]; then
    model=$(tr -d '\0' < /proc/device-tree/model)
  elif [ -f /etc/rpi-issue ]; then
    model=$(head -n1 /etc/rpi-issue)
  else
    echo "0"
    return
  fi

  case "$model" in
    *"Raspberry Pi Zero"*) echo "0" ;;
    *"Raspberry Pi 1"*)    echo "1" ;;
    *"Raspberry Pi 2"*)    echo "2" ;;
    *"Raspberry Pi 3"*)    echo "3" ;;
    *"Raspberry Pi 4"*)    echo "4" ;;
    *"Raspberry Pi 5"*)    echo "5" ;;
    *)                     echo "0" ;;
  esac
}

get_pi_serial() {
  local serial="UNKNOWN"

  if [ -f /sys/firmware/devicetree/base/serial-number ]; then
    serial=$(tr -d '\0' < /sys/firmware/devicetree/base/serial-number)
  else
    serial=$(awk '/^Serial/ {print $3}' /proc/cpuinfo 2>/dev/null || echo "UNKNOWN")
  fi

  # Strip leading zeros from the serial
  serial=$(echo "$serial" | sed 's/^0*//')

  # If everything was zeros, keep a single "0"
  [ -z "$serial" ] && serial="0"

  echo "$serial"
}


CHECKPOINT_FILE="$HOME/.rpi_setup_checkpoint"
save_checkpoint() {
  # simple: record last checkpoint name (not used for control here, just info)
  atomic_write "$CHECKPOINT_FILE" "$1" 600
  log_progress "Checkpoint saved: $1"
}

prompt_feature_toggle() {
  local feature="$1"
  local state="$2"
  local info="$3"
  local enable_cmd="$4"
  local disable_cmd="$5"
  echo ""
  echo "$feature is currently $state. ${CYAN}$info${NC}"
  echo "Choose:"
  echo "  [e]nable"
  echo "  [d]isable"
  echo "  [l]eave as-is (default)"
  read -r -p "Select action [l]: " action
  action="${action,,}" # lowercase
  if [[ -z "$action" ]]; then action="l"; fi
  case "$action" in
    e) 
      log_info "Enabling $feature..."
      if eval "$enable_cmd"; then
        log_success "$feature enabled"
      else
        log_error "Failed to enable $feature"
        return 1
      fi
      ;;
    d) 
      log_info "Disabling $feature..."
      if eval "$disable_cmd"; then
        log_success "$feature disabled"
      else
        log_error "Failed to disable $feature"
        return 1
      fi
      ;;
    *) log_info "Leaving $feature as is." ;;
  esac
  return 0
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

SCRIPT_VERSION="2025-11-21a"
STATE_FILE="$HOME/.rpi_setup_state"
LOG_FILE="$HOME/.rpi_setup.log"
LOCK_DIR="/tmp/rpi_setup.lock"
DRY_RUN=0

# Initialize system paths (will be set by check_system_compatibility)
BOOT_CONFIG=""
BOOT_CMDLINE=""
NETWORK_MANAGER=""
OS_VERSION=""

# Banner
clear
cat <<EOF
╔══════════════════════════════════════════════════════╗
║  MML Universal Raspberry Pi Setup Script             ║
║                                                      ║
╚══════════════════════════════════════════════════════╝

Version: $SCRIPT_VERSION$(printf "%*s" $((46 - ${#SCRIPT_VERSION} - 16)) "")

EOF

run_neofetch_if_installed

echo ""
log_info "Version: $SCRIPT_VERSION"
echo ""

setup_logging() {
  touch "$LOG_FILE"
  chmod 600 "$LOG_FILE"
  log_info "=== Script started at $(date) ===" >> "$LOG_FILE"
  log_info "Version: $SCRIPT_VERSION" >> "$LOG_FILE"
}

setup_logging

# Atomic lock dir creation
if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  log_error "Lock file exists, another instance is running."
  exit 1
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null' EXIT

# Run system compatibility check
check_system_compatibility

############################################################
# Checkpoints
############################################################

CHECKPOINTS=(
  START
  LOCALE
  DETECT
  PROFILE
  HOSTNAME
  NETWORK
  SWAP
  UPDATE
  UPGRADE
  ESSENTIAL
  SECURITY
  VNC
  GIT
  EMAIL
  RASPI_CONFIG
  PYTHON
  ALIASES
  COMPLETE
)

############################################################
# Individual checkpoint logic
############################################################

run_START() {
  log_info "START: Script initialized."
  save_checkpoint "START"
}

run_LOCALE() {
  log_info "Configuring locale..."
  if sudo apt-get install -y locales && \
     sudo locale-gen en_GB.UTF-8 && \
     sudo update-locale LANG=en_GB.UTF-8; then
    log_success "Locale configured"
    save_checkpoint "LOCALE"
  else
    log_error "Locale configuration failed"
    return 1
  fi
}

run_DETECT() {
  log_info "Hardware detection complete"
  if [ -f /proc/device-tree/model ]; then
    log_info "Model: $(tr -d '\0' < /proc/device-tree/model)"
  fi
  save_checkpoint "DETECT"
}

run_HOSTNAME() {
  local current_hostname
  current_hostname=$(hostname)

  # Ensure a profile is selected (and available in STATE_FILE)
  local profile=""
  if [ -f "$STATE_FILE" ]; then
    profile=$(grep '^PROFILE=' "$STATE_FILE" 2>/dev/null | cut -d= -f2 | awk '{print $1}' || true)
  fi

  if [ -z "$profile" ]; then
    log_info "Profile not set; running PROFILE checkpoint before generating hostname..."
    run_PROFILE
    if [ -f "$STATE_FILE" ]; then
      profile=$(grep '^PROFILE=' "$STATE_FILE" 2>/dev/null | cut -d= -f2 | awk '{print $1}' || true)
    fi
  fi

  local profile_code
  profile_code=$(get_profile_code "$profile")

  local pi_version
  pi_version=$(get_pi_version)

  local serial
  serial=$(get_pi_serial)

  # Generate random hex sections for the trailing pattern XXXX-XXX0x
  local rand1 rand2
  rand1=$(tr -dc 'A-F0-9' </dev/urandom | head -c4 2>/dev/null || echo "ABCD")
  rand2=$(tr -dc 'A-F0-9' </dev/urandom | head -c3 2>/dev/null || echo "EFG")

  local suggested_hostname="LH-PI0X-${pi_version}-${serial}-${profile_code}-AAAA-BBB0x"

  # Safety check in case something weird happens
  if ! validate_hostname "$suggested_hostname"; then
    log_warning "Auto-generated hostname '$suggested_hostname' failed validation, falling back to current hostname."
    suggested_hostname="$current_hostname"
  fi

  echo ""
  log_info "Suggested hostname (based on Pi version, serial & profile):"
  echo "  $suggested_hostname"
  echo ""
  read -r -p "Enter desired hostname (leave blank to use suggested, current: $current_hostname): " input

  local new_hostname
  if [ -z "$input" ]; then
    new_hostname="$suggested_hostname"
  else
    if validate_hostname "$input"; then
      new_hostname="$input"
    else
      log_warning "Invalid hostname. Using suggested hostname instead."
      new_hostname="$suggested_hostname"
    fi
  fi

  log_info "Setting hostname to $new_hostname"

  if echo "$new_hostname" | sudo tee /etc/hostname >/dev/null && \
     sudo hostnamectl set-hostname "$new_hostname" 2>/dev/null; then
    log_success "Hostname set: $new_hostname"
    save_checkpoint "HOSTNAME"
  else
    log_error "Failed to set hostname"
    return 1
  fi
}

run_NETWORK() {
  local iface
  read -r -p "Configure static network interface? (enter iface, blank=skip): " iface
  if [[ -n "$iface" ]]; then
    if ! ip link show "$iface" >/dev/null 2>&1; then
      log_error "Interface $iface does not exist"
      local available
      available=$(ip -o link show | awk -F': ' '{print $2}')
      log_info "Available interfaces: $available"
      return 1
    fi
    
    local ip gw dns
    read -r -p "Enter static IP (CIDR, e.g. 192.168.1.50/24): " ip
    read -r -p "Enter gateway/router (e.g. 192.168.1.1): " gw
    read -r -p "Enter DNS server (e.g. 8.8.8.8) [same as gateway]: " dns
    dns="${dns:-$gw}"
    
    if validate_cidr "$ip" && validate_ip "$gw" && validate_ip "$dns"; then
      if [[ "$NETWORK_MANAGER" == "dhcpcd" ]]; then
        log_info "Configuring dhcpcd..."
        backup_config_file /etc/dhcpcd.conf
        sudo sed -i '/interface '"$iface"'/,/^$/d' /etc/dhcpcd.conf
        {
          echo ""
          echo "interface $iface"
          echo "static ip_address=$ip"
          echo "static routers=$gw"
          echo "static domain_name_servers=$dns"
        } | sudo tee -a /etc/dhcpcd.conf >/dev/null
        sudo systemctl restart dhcpcd || true
      elif [[ "$NETWORK_MANAGER" == "NetworkManager" ]]; then
        log_info "Configuring NetworkManager..."
        sudo nmcli con mod "$iface" ipv4.addresses "$ip" \
                                     ipv4.gateway "$gw" \
                                     ipv4.dns "$dns" \
                                     ipv4.method manual
        sudo nmcli con down "$iface" && sudo nmcli con up "$iface"
      else
        log_warning "Unknown network manager, skipping configuration"
      fi
      log_success "Static IP configured"
    else
      log_error "Invalid IP, gateway, or DNS format."
      return 1
    fi
  else
    log_info "Network config skipped"
  fi
  save_checkpoint "NETWORK"
}

run_SWAP() {
  local current_swap
  current_swap=$(free -m | awk '/^Swap:/ {print $2}')
  local state
  state=$([ "$current_swap" -ge 1024 ] && echo "enabled" || echo "disabled")
  
  local enable_swap_cmd='sudo dphys-swapfile swapoff; sudo sed -i "s/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/" /etc/dphys-swapfile && sudo dphys-swapfile setup && sudo dphys-swapfile swapon'
  local disable_swap_cmd='sudo dphys-swapfile swapoff; sudo sed -i "s/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=100/" /etc/dphys-swapfile && sudo dphys-swapfile setup && sudo dphys-swapfile swapon'
  
  prompt_feature_toggle "1024MB Swap" "$state" "Current MB: $current_swap" \
    "$enable_swap_cmd" \
    "$disable_swap_cmd"
  save_checkpoint "SWAP"
}

run_UPDATE() {
  log_info "Updating package lists..."
  if sudo apt-get update -y; then
    log_success "Package lists updated."
    save_checkpoint "UPDATE"
  else
    log_error "Package update failed"
    return 1
  fi
}

run_UPGRADE() {
  log_info "Upgrading system packages..."
  if sudo apt-get upgrade -y; then
    log_success "Packages upgraded."
    save_checkpoint "UPGRADE"
  else
    log_error "Package upgrade failed"
    return 1
  fi
}

run_ESSENTIAL() {
  local packages=(curl wget git vim htop tree unzip apt-transport-https ca-certificates gnupg lsb-release net-tools ufw arping neofetch)
  if install_packages "${packages[@]}"; then
    log_success "Essential packages installed."
    save_checkpoint "ESSENTIAL"
  else
    log_error "Essential package installation failed"
    return 1
  fi
}

run_SECURITY() {
  local ufw
  ufw=$(sudo ufw status 2>/dev/null | grep -qw "active" && echo "enabled" || echo "disabled")
  
  local enable_cmd='sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw allow ssh && sudo ufw --force enable'
  local disable_cmd='sudo ufw disable'
  
  prompt_feature_toggle "Firewall (UFW)" "$ufw" "Current status: $ufw" \
    "$enable_cmd" \
    "$disable_cmd"
  
  if prompt_yn "Harden SSH configuration? (disable root login, set timeouts) (y/n) [n]:" n; then
    backup_config_file /etc/ssh/sshd_config
    sudo sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*ClientAliveInterval.*/ClientAliveInterval 300/' /etc/ssh/sshd_config
    sudo sed -i 's/^#*ClientAliveCountMax.*/ClientAliveCountMax 2/' /etc/ssh/sshd_config
    if sudo systemctl restart ssh; then
      log_success "SSH hardened"
    else
      log_error "SSH restart failed"
    fi
  fi
  
  if prompt_yn "Install fail2ban for brute-force protection? (y/n) [n]:" n; then
    if install_packages fail2ban; then
      sudo systemctl enable --now fail2ban
      log_success "fail2ban installed and enabled"
    fi
  fi
  
  save_checkpoint "SECURITY"
}

run_VNC() {
  local vnc
  vnc=$(systemctl is-enabled vncserver-x11-serviced.service 2>/dev/null | grep -q enabled && echo "enabled" || echo "disabled")
  prompt_feature_toggle "VNC" "$vnc" "Current status: $vnc" \
    "sudo systemctl enable --now vncserver-x11-serviced.service" \
    "sudo systemctl disable --now vncserver-x11-serviced.service"
  save_checkpoint "VNC"
}

run_GIT() {
  local user
  user="$(git config --global user.name 2>/dev/null || echo "")"
  local email
  email="$(git config --global user.email 2>/dev/null || echo "")"
  log_info "Current git user: ${user:-not set}, email: ${email:-not set}"
  read -r -p "New git username (leave blank to keep '$user'): " newuser
  [ -n "$newuser" ] && user="$newuser"
  read -r -p "New git email (leave blank to keep '$email'): " newemail
  [ -n "$newemail" ] && email="$newemail"
  if [[ -n "$user" ]]; then git config --global user.name "$user"; fi
  if [[ -n "$email" ]]; then git config --global user.email "$email"; fi
  log_success "Git configured as $user <$email>"
  save_checkpoint "GIT"
}

run_EMAIL() {
  log_info "Current email config: $(grep from ~/.msmtprc 2>/dev/null | grep -oE '[^ ]+$' || echo "not set")"
  read -r -p "Configure email (for msmtp)? (y/n) [n]: " ans
  if [[ "${ans,,}" == "y" ]]; then
    read -r -p "Please enter Gmail address: " email_address
    echo "Create Gmail App Password at: https://myaccount.google.com/apppasswords"
    read -rs -p "Gmail App Password: " app_pass; echo
    
    log_warning "Password will be stored in ~/.secrets_msmtp_pass with 600 permissions"
    log_warning "Consider encrypting your home directory for better security"
    
    if install_packages msmtp msmtp-mta; then
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
      
      if prompt_yn "Send test email to verify configuration? (y/n) [n]:" n; then
        echo "Test email from Raspberry Pi at $(date)" | msmtp "$email_address" && \
          log_success "Test email sent successfully" || \
          log_warning "Test email failed - check configuration"
      fi
    else
      log_error "Failed to install msmtp packages"
      return 1
    fi
  else
    log_info "Skipped msmtp email setup."
  fi
  save_checkpoint "EMAIL"
}

run_RASPI_CONFIG() {
  local spi
  spi=$(grep -q '^dtparam=spi=on' "$BOOT_CONFIG" 2>/dev/null && echo "enabled" || echo "disabled")
  local i2c
  i2c=$(grep -q '^dtparam=i2c_arm=on' "$BOOT_CONFIG" 2>/dev/null && echo "enabled" || echo "disabled")
  local cam
  cam=$(vcgencmd get_camera 2>/dev/null | grep -q 'supported=1 detected=1' && echo "enabled" || echo "disabled")
  
  backup_config_file "$BOOT_CONFIG"
  
  prompt_feature_toggle "SPI" "$spi" "Current: $spi" \
    "sudo raspi-config nonint do_spi 0" \
    "sudo raspi-config nonint do_spi 1"
  prompt_feature_toggle "I2C" "$i2c" "Current: $i2c" \
    "sudo raspi-config nonint do_i2c 0" \
    "sudo raspi-config nonint do_i2c 1"
  prompt_feature_toggle "Camera" "$cam" "Current: $cam" \
    "sudo raspi-config nonint do_camera 0" \
    "sudo raspi-config nonint do_camera 1"
  save_checkpoint "RASPI_CONFIG"
}

run_PYTHON() {
  local pkg
  pkg="$(pip3 list 2>/dev/null | grep -qw requests && echo "installed" || echo "not installed")"
  prompt_feature_toggle "requests (Python package)" "$pkg" "Current state: $pkg" \
    "pip3 install --user --upgrade requests" \
    "pip3 uninstall -y requests"
  save_checkpoint "PYTHON"
}

run_PROFILE() {
  local pfchoice
  pfchoice="$(grep PROFILE= $STATE_FILE 2>/dev/null | cut -d= -f2 | grep -oE '[^ ]+' || echo "not set")"
  local profiles=("generic" "web" "iot" "media" "dev")
  echo "Current profile: $pfchoice"
  echo "Available profiles:"
  for i in "${!profiles[@]}"; do echo "  $((i+1))) ${profiles[$i]}"; done
  read -r -p "Select profile number [1]: " pnum
  pnum="${pnum:-1}"
  local profsel=${profiles[$((pnum-1))]}
  local profcode
  profcode=$(get_profile_code "$profsel")
  log_info "Profile selected: $profsel (code: $profcode)"
  echo "PROFILE=${profsel}" > "$STATE_FILE"
  save_checkpoint "PROFILE"
}

run_ALIASES() {
  mkdir -p ~/projects ~/scripts ~/backup ~/logs
  if ! grep -q "# === Custom Aliases ===" ~/.bashrc 2>/dev/null; then
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

run_INFO_SCRIPT() {
  local email

  echo ""
  read -r -p "Enter email for system info report [mmlawlessuk@gmail.com]: " email
  email="${email:-mmlawlessuk@gmail.com}"

  log_info "Running mml_rpi_info.sh for $email"

  # Run the remote script; handle success/failure without killing this script
  if curl -fsSL https://raw.githubusercontent.com/mmlawless/mml_rpi_info/main/mml_rpi_info.sh \
    | bash -s -- --email "$email"; then
    log_success "System info/email script completed successfully."
  else
    log_error "System info/email script failed. Please check your network or URL."
  fi
}

run_COMPLETE() {
  save_checkpoint "COMPLETE"
  log_success "All checkpoints completed!"
}

run_checkpoint_by_name() {
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
    *) log_warning "Unknown checkpoint $name"; return 1 ;;
  esac
}

##########################################################
# Menu-driven main loop
##########################################################

main_menu() {
  while true; do
    echo ""
    echo "================ Setup Menu ================"
echo "1) Run ALL checkpoints (full setup)"
echo "2) Run a SINGLE checkpoint"
echo "3) Run system info/email script (mml_rpi_info)"
echo "4) Quit"
echo "==========================================="
read -r -p "Select an option [1/2/3/4]: " choice
choice="${choice%%[$'\r\n\t ']*}"

case "$choice" in
  1|"")
    # Run all checkpoints in order
    echo ""
    log_info "Running ALL checkpoints..."
    for cp in "${CHECKPOINTS[@]}"; do
      echo ""
      log_info ">>> Running checkpoint: $cp"
      if run_checkpoint_by_name "$cp"; then
        log_success "Checkpoint $cp completed."
      else
        log_warning "Checkpoint $cp reported a failure; continuing."
      fi
    done
    break
    ;;
  2)
    echo ""
    echo "Available checkpoints:"
    local idx=1
    for cp in "${CHECKPOINTS[@]}"; do
      printf "  %2d) %s\n" "$idx" "$cp"
      idx=$((idx+1))
    done
    read -r -p "Enter checkpoint number to run: " num
    if [[ "$num" =~ ^[0-9]+$ ]] && (( num >= 1 )) && (( num <= ${#CHECKPOINTS[@]} )); then
      local sel="${CHECKPOINTS[$((num-1))]}"
      echo ""
      log_info "Running single checkpoint: $sel"
      if run_checkpoint_by_name "$sel"; then
        log_success "Checkpoint $sel completed."
      else
        log_warning "Checkpoint $sel reported a failure."
      fi
    else
      log_warning "Invalid selection."
    fi
    ;;
  3)
    echo ""
    log_info "Running system info/email script..."
    run_INFO_SCRIPT
    ;;
  4|q|Q)
    log_info "Quitting setup menu."
    break
    ;;
  *)
    log_warning "Unknown choice. Please enter 1, 2, 3, or 4."
    ;;
esac
  done
}

main_menu

############################################################
# Summary and reboot prompt
############################################################

CURRENT_SWAP=$(free -m | awk '/^Swap:/ {print $2}')
SWAP_STATE=$([ "$CURRENT_SWAP" -ge 1024 ] && echo "enabled" || echo "disabled")
VNC_SERVICE_STATUS=$(systemctl is-enabled vncserver-x11-serviced.service 2>/dev/null | grep -q enabled && echo "enabled" || echo "disabled")
UFW_STATUS=$(sudo ufw status 2>/dev/null | grep -qw "active" && echo "enabled" || echo "disabled")
SPI_STATE=$(grep -q '^dtparam=spi=on' "$BOOT_CONFIG" 2>/dev/null && echo "enabled" || echo "disabled")
I2C_STATE=$(grep -q '^dtparam=i2c_arm=on' "$BOOT_CONFIG" 2>/dev/null && echo "enabled" || echo "disabled")
CAMERA_STATE=$(vcgencmd get_camera 2>/dev/null | grep -q 'supported=1 detected=1' && echo "enabled" || echo "disabled")
GIT_NAME="$(git config --global user.name 2>/dev/null || echo "not set")"
GIT_EMAIL="$(git config --global user.email 2>/dev/null || echo "not set")"
PYTHON_PKGS_INSTALLED=$(pip3 list 2>/dev/null | grep -qw requests && echo "installed" || echo "not installed")
PROFILE_STATUS="$(grep PROFILE= $STATE_FILE 2>/dev/null | cut -d= -f2 | grep -oE '[^ ]+' || echo "not set")"
HOSTNAME_DISPLAY="$(hostname)"

echo ""
echo "=========================================="
log_success "Setup run completed!"
echo "=========================================="
echo ""
echo "System Information:"
if [ -f /proc/device-tree/model ]; then
  echo "  Model: $(tr -d '\0' < /proc/device-tree/model)"
fi
echo "  OS: $(grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"')"
echo "  Kernel: $(uname -r)"
echo "  Boot Config: $BOOT_CONFIG"
echo "  Network Manager: $NETWORK_MANAGER"
echo ""
echo "Configuration:"
echo "  Hostname: $HOSTNAME_DISPLAY"
echo "  Profile: $PROFILE_STATUS"
echo "  Swap: $SWAP_STATE (${CURRENT_SWAP:-0} MB)"
echo "  SPI: $SPI_STATE"
echo "  I2C: $I2C_STATE"
echo "  Camera: $CAMERA_STATE"
echo "  VNC: $VNC_SERVICE_STATUS"
echo "  Firewall (UFW): $UFW_STATUS"
echo "  Git: $GIT_NAME <$GIT_EMAIL>"
echo "  Python requests: $PYTHON_PKGS_INSTALLED"
echo ""

run_neofetch_if_installed

# Offer to run the info/email script before reboot
echo ""
if prompt_yn "Run system info/email script now? (y/n) [n]:" n; then
  run_INFO_SCRIPT
fi

log_warning "Reboot recommended to finalize all changes!"
echo ""
if prompt_yn "Reboot now? (y/n) [n]:" n; then
  log_info "Rebooting in 5 seconds... (Ctrl+C to cancel)"
  sleep 5
  sudo reboot
else
  log_info "Remember to reboot when convenient: sudo reboot"
  log_success "Setup complete! Enjoy your Raspberry Pi!"
fi
