#!/bin/bash
set -euo pipefail

############################################################
# Universal Raspberry Pi Setup Script
# Version: 2024-10-20-Enhanced
# Features: Multi-tier support, profiles, checkpointing,
#           temperature monitoring, piwheels, recovery
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
# Locale fix
############################################################
setup_locale() {
  if ! locale -a 2>/dev/null | grep -qi '^en_GB\.utf8$'; then
    log_info "Setting up en_GB.UTF-8 locale..."
    sudo apt-get update -y
    sudo apt-get install -y locales
    sudo sed -i 's/^# *en_GB.UTF-8 UTF-8/en_GB.UTF-8 UTF-8/' /etc/locale.gen
    sudo locale-gen en_GB.UTF-8
    sudo update-locale LANG=en_GB.UTF-8
  fi
  export LANG=en_GB.UTF-8
  export LC_ALL=en_GB.UTF-8
}

############################################################
# Utilities and colour setup
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
    --non-interactive)
      NON_INTERACTIVE=1
      shift
      ;;
    --tier)
      PRESET_TIER="$2"
      shift 2
      ;;
    --profile)
      PRESET_PROFILE="$2"
      shift 2
      ;;
    --force)
      FORCE_RERUN=1
      shift
      ;;
    --help)
      echo "Usage: $0 [OPTIONS]"
      echo "Options:"
      echo "  --non-interactive       Run without prompts (use defaults)"
      echo "  --tier TIER            Set performance tier (MINIMAL/LOW/MEDIUM/HIGH)"
      echo "  --profile PROFILE      Set installation profile (generic/web/iot/media/dev)"
      echo "  --force                Force rerun even if already completed"
      echo "  --help                 Show this help message"
      exit 0
      ;;
    *)
      log_error "Unknown option: $1"
      exit 1
      ;;
  esac
done

prompt_yn() {
  local question="$1" default="${2:-n}" ans
  if [ "$NON_INTERACTIVE" -eq 1 ]; then
    log_info "Non-interactive mode: defaulting '$question' to $default"
    ans="$default"
  elif [ "$IS_TTY" -eq 1 ]; then
    read -r -p "$question" ans < /dev/tty || ans="$default"
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
    read -r -p "$prompt" var < /dev/tty
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
    local temp_str
    temp_str=$(vcgencmd measure_temp 2>/dev/null || echo "temp=0.0'C")
    local temp
    temp=$(echo "$temp_str" | grep -oP '\d+\.\d+' | head -1)
    
    if [ -n "$temp" ]; then
      local temp_int
      temp_int=$(echo "$temp" | cut -d. -f1)
      
      if [ "$temp_int" -gt 80 ]; then
        log_temp "CPU Temperature: ${temp}°C - CRITICAL! Pausing for cooldown..."
        sleep 30
        return 1
      elif [ "$temp_int" -gt 70 ]; then
        log_temp "CPU Temperature: ${temp}°C - High, slowing down..."
        sleep 10
        return 0
      else
        return 0
      fi
    fi
  fi
  return 0
}

############################################################
# Checkpointing system
############################################################
save_checkpoint() {
  local checkpoint="$1"
  echo "$checkpoint" > "$CHECKPOINT_FILE"
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
}

is_checkpoint_passed() {
  local checkpoint="$1"
  local current
  current=$(load_checkpoint)
  
  case "$current" in
    START) return 1 ;;
    LOCALE) [[ "$checkpoint" == "START" ]] ;;
    DETECT) [[ "$checkpoint" =~ ^(START|LOCALE)$ ]] ;;
    SWAP) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT)$ ]] ;;
    UPDATE) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP)$ ]] ;;
    UPGRADE) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE)$ ]] ;;
    ESSENTIAL) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE|UPGRADE)$ ]] ;;
    SECURITY) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE|UPGRADE|ESSENTIAL)$ ]] ;;
    HOSTNAME) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY)$ ]] ;;
    GIT) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|HOSTNAME)$ ]] ;;
    EMAIL) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|HOSTNAME|GIT)$ ]] ;;
    RASPI_CONFIG) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|HOSTNAME|GIT|EMAIL)$ ]] ;;
    PYTHON) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|HOSTNAME|GIT|EMAIL|RASPI_CONFIG)$ ]] ;;
    PROFILE) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|HOSTNAME|GIT|EMAIL|RASPI_CONFIG|PYTHON)$ ]] ;;
    ALIASES) [[ "$checkpoint" =~ ^(START|LOCALE|DETECT|SWAP|UPDATE|UPGRADE|ESSENTIAL|SECURITY|HOSTNAME|GIT|EMAIL|RASPI_CONFIG|PYTHON|PROFILE)$ ]] ;;
    COMPLETE) return 0 ;;
    *) return 1 ;;
  esac
}

############################################################
# State management for profile switching
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
    source "$STATE_FILE"
    return 0
  fi
  return 1
}

############################################################
# Detect Pi info
############################################################
detect_pi_info() {
  PI_MODEL="unknown"
  PI_MEMORY=0
  PI_ARCH="unknown"
  PI_SERIAL="UNKNOWN"
  
  PI_ARCH=$(uname -m)
  
  # Get serial number
  if [ -f /proc/cpuinfo ]; then
    PI_SERIAL=$(grep Serial /proc/cpuinfo | awk '{print $3}' | tail -c 9)
    [ -z "$PI_SERIAL" ] && PI_SERIAL="UNKNOWN"
  fi
  
  if [ -f /proc/device-tree/model ]; then
    MODEL_STRING=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')
    
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
# Pi Model Selection
############################################################
select_pi_model() {
  if [ -n "$PRESET_TIER" ]; then
    PERF_TIER="$PRESET_TIER"
    log_info "Using preset tier: $PERF_TIER"
    return
  fi
  
  echo ""
  echo "=========================================="
  echo "Select Your Raspberry Pi Model"
  echo "=========================================="
  echo "Auto-detected: Pi $PI_MODEL with ${PI_MEMORY}MB RAM"
  echo ""
  echo "1) Pi Zero / Zero W (ARMv6, 512MB)"
  echo "2) Pi 1 Model B/B+ (ARMv6, 256-512MB)"
  echo "3) Pi 2 Model B (ARMv7, 1GB)"
  echo "4) Pi 3 Model B/B+ (ARMv8, 1GB)"
  echo "5) Pi 4 Model B (ARMv8, 1-8GB)"
  echo "6) Use auto-detected values"
  echo "7) Manual override"
  echo ""
  
  local choice
  choice=$(read_tty "Enter choice [1-7] (default: 6): ")
  choice=${choice:-6}
  
  case $choice in
    1) PI_MODEL="0"; PI_MEMORY=512; PI_ARCH="armv6l" ;;
    2)
      PI_MODEL="1"
      local mem_choice
      mem_choice=$(read_tty "Memory size? [256/512] (default: 512): ")
      PI_MEMORY=${mem_choice:-512}
      PI_ARCH="armv6l"
      ;;
    3) PI_MODEL="2"; PI_MEMORY=1024; PI_ARCH="armv7l" ;;
    4) PI_MODEL="3"; PI_MEMORY=1024; PI_ARCH="armv8" ;;
    5)
      PI_MODEL="4"
      local mem_choice
      mem_choice=$(read_tty "Memory size? [1024/2048/4096/8192] (default: 2048): ")
      PI_MEMORY=${mem_choice:-2048}
      PI_ARCH="armv8"
      ;;
    6) log_info "Using auto-detected values" ;;
    7)
      PI_MODEL=$(read_tty "Enter Pi model (0/1/2/3/4/5): ")
      PI_MEMORY=$(read_tty "Enter RAM in MB: ")
      PI_ARCH=$(read_tty "Enter architecture (armv6l/armv7l/armv8): ")
      ;;
    *) log_warning "Invalid choice, using auto-detected values" ;;
  esac
  
  set_performance_tier
  
  echo ""
  log_info "Configuration: Pi $PI_MODEL, ${PI_MEMORY}MB RAM, $PI_ARCH"
  log_info "Performance tier: $PERF_TIER"
  log_info "Serial: $PI_SERIAL"
  echo ""
}

############################################################
# Performance Tier Configuration
############################################################
set_performance_tier() {
  if [[ "$PI_MODEL" == "4" ]] || [[ "$PI_MODEL" == "5" ]]; then
    PERF_TIER="HIGH"
  elif [[ "$PI_MODEL" == "2" ]] || [[ "$PI_MODEL" == "3" ]]; then
    PERF_TIER="MEDIUM"
  elif [ "$PI_MEMORY" -le 512 ]; then
    PERF_TIER="LOW"
  else
    PERF_TIER="MEDIUM"
  fi
  
  if [ "$PI_MEMORY" -le 256 ]; then
    PERF_TIER="MINIMAL"
  fi
}

############################################################
# Profile Selection
############################################################
PROFILE="generic"
PROFILE_ABBREV="GEN"

select_profile() {
  if [ -n "$PRESET_PROFILE" ]; then
    PROFILE="$PRESET_PROFILE"
    set_profile_abbrev
    log_info "Using preset profile: $PROFILE ($PROFILE_ABBREV)"
    return
  fi
  
  echo ""
  echo "=========================================="
  echo "Select Installation Profile"
  echo "=========================================="
  echo "1) Generic - Basic tools and utilities (GEN)"
  echo "2) Web Server - Nginx, PHP, MySQL/MariaDB (WEB)"
  echo "3) IoT Sensor - MQTT, sensors, GPIO libraries (IOT)"
  echo "4) Media Center - Media playback tools (MED)"
  echo "5) Development - Full dev environment (DEV)"
  echo ""
  
  local choice
  choice=$(read_tty "Enter choice [1-5] (default: 1): ")
  choice=${choice:-1}
  
  case $choice in
    1) PROFILE="generic"; PROFILE_ABBREV="GEN" ;;
    2) PROFILE="web"; PROFILE_ABBREV="WEB" ;;
    3) PROFILE="iot"; PROFILE_ABBREV="IOT" ;;
    4) PROFILE="media"; PROFILE_ABBREV="MED" ;;
    5) PROFILE="dev"; PROFILE_ABBREV="DEV" ;;
    *) PROFILE="generic"; PROFILE_ABBREV="GEN" ;;
  esac
  
  log_info "Selected profile: $PROFILE ($PROFILE_ABBREV)"
}

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

############################################################
# Hostname configuration
############################################################
set_hostname() {
  NEW_HOSTNAME="LH-PI${PI_MODEL}-${PI_SERIAL}-${PROFILE_ABBREV}"
  CURRENT_HOSTNAME=$(hostname)
  
  log_info "Current hostname: $CURRENT_HOSTNAME"
  log_info "Proposed hostname: $NEW_HOSTNAME"
  
  if [ "$CURRENT_HOSTNAME" = "$NEW_HOSTNAME" ]; then
    log_info "Hostname already set correctly"
    return
  fi
  
  if prompt_yn "Set hostname to $NEW_HOSTNAME? (y/n): " y; then
    echo "$NEW_HOSTNAME" | sudo tee /etc/hostname > /dev/null
    sudo sed -i "s/127.0.1.1.*/127.0.1.1\t$NEW_HOSTNAME/" /etc/hosts
    sudo hostnamectl set-hostname "$NEW_HOSTNAME" 2>/dev/null || true
    log_success "Hostname set to $NEW_HOSTNAME (takes effect after reboot)"
  else
    NEW_HOSTNAME="$CURRENT_HOSTNAME"
    log_info "Keeping current hostname"
  fi
}

############################################################
# Swap setup
############################################################
setup_swap() {
  if [ "$PI_MEMORY" -le 512 ]; then
    log_info "Low memory detected (${PI_MEMORY}MB). Checking swap..."
    
    local current_swap
    current_swap=$(free -m | awk '/^Swap:/ {print $2}')
    
    if [ "$current_swap" -lt 1024 ]; then
      log_warning "Current swap is ${current_swap}MB"
      if prompt_yn "Increase swap to 1024MB for package compilation? (y/n): " y; then
        log_info "Setting up swap file (this may take a few minutes)..."
        
        sudo dphys-swapfile swapoff 2>/dev/null || true
        
        sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile 2>/dev/null || \
          echo "CONF_SWAPSIZE=1024" | sudo tee -a /etc/dphys-swapfile > /dev/null
        
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
# Progress indicator for long operations
############################################################
show_progress() {
  local duration=$1
  local message=$2
  local elapsed=0
  
  while [ $elapsed -lt $duration ]; do
    printf "\r${CYAN}[PROGRESS]${NC} $message... %d/%d seconds" $elapsed $duration
    sleep 5
    elapsed=$((elapsed + 5))
    check_temperature || sleep 20
  done
  printf "\r${CYAN}[PROGRESS]${NC} $message... Complete!          \n"
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

# Check for recovery
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

# Check if already completed
if load_state && [ "$FORCE_RERUN" -eq 0 ]; then
  log_info "Previous installation detected:"
  log_info "  Profile: $PROFILE ($PROFILE_ABBREV)"
  log_info "  Tier: $PERF_TIER"
  log_info "  Hostname: $HOSTNAME"
  log_info "  Date: $INSTALL_DATE"
  echo ""
  
  if prompt_yn "Would you like to switch to a different profile? (y/n): " n; then
    log_info "Profile switching mode activated"
    detect_pi_info
    select_profile
    
    if [ "$PROFILE" != "$(grep PROFILE= "$STATE_FILE" | cut -d= -f2)" ]; then
      log_info "Switching from previous profile to $PROFILE"
      # Skip to profile installation
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
# Locale
############################################################
if ! is_checkpoint_passed "LOCALE"; then
  setup_locale
  save_checkpoint "LOCALE"
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
# Hostname
############################################################
if ! is_checkpoint_passed "HOSTNAME"; then
  set_hostname
  save_checkpoint "HOSTNAME"
fi

############################################################
# Swap
############################################################
if ! is_checkpoint_passed "SWAP"; then
  if [[ "$PERF_TIER" == "LOW" ]] || [[ "$PERF_TIER" == "MINIMAL" ]]; then
    setup_swap
  fi
  save_checkpoint "SWAP"
fi

############################################################
# System update
############################################################
if ! is_checkpoint_passed "UPDATE"; then
  log_info "Updating package lists..."
  if ! sudo apt-get update -y; then
    log_error "Failed to update package lists"
    exit 1
  fi
  save_checkpoint "UPDATE"
fi

############################################################
# System upgrade
############################################################
if ! is_checkpoint_passed "UPGRADE"; then
  if [[ "$PERF_TIER" == "MINIMAL" ]]; then
    log_warning "Very low memory detected. Upgrade will be slow and may take hours."
    if ! prompt_yn "Proceed with full system upgrade? (y/n): " y; then
      log_info "Skipping upgrade. You can run 'sudo apt upgrade' manually later."
      save_checkpoint "UPGRADE"
    else
      log_info "Upgrading packages (this will take a LONG time on low-spec Pi)..."
      (sudo apt-get upgrade -y &) && show_progress 3600 "Upgrading system packages"
      wait
      save_checkpoint "UPGRADE"
    fi
  else
    log_info "Upgrading installed packages (this may take a while)..."
    if [[ "$PERF_TIER" == "LOW" ]]; then
      log_warning "This may take 30-60 minutes on older Pi models..."
      (sudo apt-get upgrade -y &) && show_progress 1800 "Upgrading system packages"
      wait
    else
      sudo apt-get upgrade -y
    fi
    save_checkpoint "UPGRADE"
  fi
  check_temperature
fi

############################################################
# Essential packages
############################################################
if ! is_checkpoint_passed "ESSENTIAL"; then
  log_info "Installing essential packages for $PERF_TIER tier system..."
  
  ESSENTIAL_PACKAGES=(
    curl wget git vim htop tree unzip
    apt-transport-https ca-certificates
    gnupg lsb-release net-tools ufw
  )
  
  if [[ "$PERF_TIER" != "MINIMAL" ]]; then
    ESSENTIAL_PACKAGES+=(build-essential)
  fi
  
  if [[ "$PERF_TIER" == "HIGH" ]] || [[ "$PERF_TIER" == "MEDIUM" ]]; then
    ESSENTIAL_PACKAGES+=(python3-pip python3-venv python3-dev)
  elif [[ "$PERF_TIER" == "LOW" ]]; then
    ESSENTIAL_PACKAGES+=(python3-pip python3-venv)
  else
    ESSENTIAL_PACKAGES+=(python3)
  fi
  
  if [[ "$PERF_TIER" == "HIGH" ]] || [[ "$PERF_TIER" == "MEDIUM" ]]; then
    if [[ "$PI_ARCH" != "armv6l" ]]; then
      if prompt_yn "Install Node.js and npm? (not recommended for ARMv6) (y/n): " n; then
        ESSENTIAL_PACKAGES+=(nodejs npm)
      fi
    fi
  fi
  
  if ! sudo apt-get install -y "${ESSENTIAL_PACKAGES[@]}"; then
    log_error "Failed to install essential packages"
    exit 1
  fi
  
  log_success "Essential packages installed"
  save_checkpoint "ESSENTIAL"
  check_temperature
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
    log_info "Enabling SSH service..."
    sudo systemctl enable --now ssh
    log_success "SSH service enabled and started"
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
      rm -f ~/.msmtprc
      rm -f ~/.secrets/msmtp.gpg
    fi
  fi

  if [ ! -f ~/.msmtprc ]; then
    if prompt_yn "Would you like to configure email (msmtp)? (y/n): " n; then
      log_info "Installing msmtp and gpg..."
      sudo apt-get install -y msmtp msmtp-mta gpg

      # Ensure secret dir exists
      mkdir -p ~/.secrets
      chmod 700 ~/.secrets

      # Read Gmail address
      email_address=$(read_tty "Enter your Gmail address: ")

      if [ -n "$email_address" ]; then
        log_warning "You need a Gmail App Password (not your regular password)"
        log_info "Create one at: https://myaccount.google.com/apppasswords"

        # Read app password securely (no echo)
        printf "Enter your Gmail App Password (16 chars, no spaces): " > /dev/tty
        stty -echo
        read -r app_password < /dev/tty || app_password=""
        stty echo
        echo > /dev/tty

        if [ -n "$app_password" ]; then
          # Encrypt app password with GPG (symmetric AES256)
          printf "%s" "$app_password" | gpg --symmetric --cipher-algo AES256 -o ~/.secrets/msmtp.gpg
          chmod 600 ~/.secrets/msmtp.gpg
          unset app_password

          # Write msmtp config using passwordeval
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
    if sudo raspi-config nonint do_expand_rootfs; then
      log_success "Filesystem expansion configured (takes effect after reboot)"
    else
      log_warning "Filesystem expansion may have already been performed"
    fi

    if prompt_yn "Allocate GPU memory? (y/n): " n; then
      local gpu_mem
      if [[ "$PERF_TIER" == "MINIMAL" ]] || [[ "$PERF_TIER" == "LOW" ]]; then
        gpu_mem=$(read_tty "GPU memory in MB [16/32/64] (default: 16 for low memory): ")
        gpu_mem=${gpu_mem:-16}
      else
        gpu_mem=$(read_tty "GPU memory in MB [64/128/256] (default: 128): ")
        gpu_mem=${gpu_mem:-128}
      fi
      
      if ! grep -q "^gpu_mem=" /boot/config.txt 2>/dev/null && ! grep -q "^gpu_mem=" /boot/firmware/config.txt 2>/dev/null; then
        if [ -f /boot/firmware/config.txt ]; then
          echo "gpu_mem=$gpu_mem" | sudo tee -a /boot/firmware/config.txt > /dev/null
        else
          echo "gpu_mem=$gpu_mem" | sudo tee -a /boot/config.txt > /dev/null
        fi
        log_success "GPU memory set to ${gpu_mem} MB (requires reboot)"
      else
        log_warning "GPU memory already configured in config.txt"
      fi
    fi

    if prompt_yn "Enable I2C interface? (y/n): " n; then
      sudo raspi-config nonint do_i2c 0
      log_success "I2C interface enabled"
    fi
    
    if prompt_yn "Enable SPI interface? (y/n): " n; then
      sudo raspi-config nonint do_spi 0
      log_success "SPI interface enabled"
    fi
    
    if prompt_yn "Enable Camera interface? (y/n): " n; then
      sudo raspi-config nonint do_camera 0
      log_success "Camera interface enabled"
    fi
  else
    log_warning "raspi-config not found, skipping Pi-specific configuration"
  fi
  save_checkpoint "RASPI_CONFIG"
fi

############################################################
# Python setup with piwheels
############################################################
if ! is_checkpoint_passed "PYTHON"; then
  if [[ "$PERF_TIER" != "MINIMAL" ]]; then
    setup_piwheels
    
    if prompt_yn "Install Python packages? (y/n): " y; then
      log_info "Installing Python packages for $PERF_TIER tier system..."
      
      PYTHON_PACKAGES=()
      
      if [[ "$PERF_TIER" == "LOW" ]]; then
        log_warning "Installing only lightweight Python packages for low-spec Pi"
        PYTHON_PACKAGES=(
          requests
          RPi.GPIO
        )
        
        if prompt_yn "Install Flask (web framework)? May be slow (y/n): " n; then
          PYTHON_PACKAGES+=(flask)
        fi
        
      elif [[ "$PERF_TIER" == "MEDIUM" ]]; then
        PYTHON_PACKAGES=(
          requests flask
          RPi.GPIO
        )
        
        if prompt_yn "Install scientific packages (numpy)? Compilation may take 15-30 min (y/n): " n; then
          log_info "Installing numpy (piwheels should provide pre-compiled wheel)..."
          PYTHON_PACKAGES+=(numpy)
        fi
        
        if prompt_yn "Install Adafruit libraries? (y/n): " n; then
          PYTHON_PACKAGES+=(
            adafruit-circuitpython-motor
            adafruit-circuitpython-servo
          )
        fi
        
      else
        PYTHON_PACKAGES=(
          numpy requests flask
          RPi.GPIO
          adafruit-circuitpython-motor
          adafruit-circuitpython-servo
        )
        
        if prompt_yn "Install matplotlib (plotting)? (y/n): " n; then
          PYTHON_PACKAGES+=(matplotlib)
        fi
      fi
      
      if [ ${#PYTHON_PACKAGES[@]} -gt 0 ]; then
        log_info "Installing: ${PYTHON_PACKAGES[*]}"
        log_info "Using piwheels for pre-compiled packages (much faster!)"
        
        if [[ "$PERF_TIER" == "LOW" ]]; then
          log_warning "Installation may take 5-15 minutes with piwheels..."
        fi
        
        if pip3 install --user --no-warn-script-location "${PYTHON_PACKAGES[@]}"; then
          log_success "Python packages installed"
          
          if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc; then
            echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
          fi
        else
          log_warning "Some Python packages may have failed to install"
          log_info "You can retry individual packages later with: pip3 install --user <package>"
        fi
      fi
    fi
  else
    log_info "Skipping Python packages for MINIMAL tier (can install manually later)"
  fi
  save_checkpoint "PYTHON"
  check_temperature
fi

############################################################
# Profile-specific installations
############################################################
if ! is_checkpoint_passed "PROFILE"; then
  log_info "Installing profile-specific packages: $PROFILE"
  
  case $PROFILE in
    web)
      log_info "Installing web server stack..."
      if [[ "$PERF_TIER" == "MINIMAL" ]]; then
        log_warning "Web server profile not recommended for MINIMAL tier"
        if ! prompt_yn "Continue anyway? (y/n): " n; then
          log_info "Skipping web server installation"
        else
          sudo apt-get install -y nginx php-fpm sqlite3 php-sqlite3
          sudo systemctl enable nginx
          sudo systemctl start nginx
          sudo ufw allow 'Nginx HTTP'
          log_success "Lightweight web stack installed (Nginx + PHP + SQLite)"
        fi
      else
        sudo apt-get install -y nginx php-fpm mariadb-server php-mysql
        sudo systemctl enable nginx mariadb
        sudo systemctl start nginx mariadb
        sudo ufw allow 'Nginx HTTP'
        log_success "Web server stack installed (Nginx + PHP + MariaDB)"
        log_info "Secure MariaDB with: sudo mysql_secure_installation"
      fi
      ;;
      
    iot)
      log_info "Installing IoT sensor stack..."
      sudo apt-get install -y mosquitto mosquitto-clients
      
      if [[ "$PERF_TIER" != "MINIMAL" ]]; then
        pip3 install --user paho-mqtt adafruit-blinka
      fi
      
      sudo systemctl enable mosquitto
      sudo systemctl start mosquitto
      sudo ufw allow 1883
      log_success "IoT stack installed (MQTT broker + clients)"
      ;;
      
    media)
      log_info "Installing media center tools..."
      if [[ "$PERF_TIER" == "MINIMAL" ]]; then
        log_warning "Media center profile not recommended for MINIMAL tier"
        sudo apt-get install -y omxplayer
      else
        sudo apt-get install -y vlc mpv youtube-dl ffmpeg
      fi
      log_success "Media tools installed"
      ;;
      
    dev)
      log_info "Installing development environment..."
      DEV_PACKAGES=(tmux screen docker.io docker-compose)
      
      if [[ "$PERF_TIER" != "MINIMAL" ]]; then
        DEV_PACKAGES+=(code)
      fi
      
      sudo apt-get install -y "${DEV_PACKAGES[@]}" || log_warning "Some dev packages may have failed"
      
      if command -v docker &> /dev/null; then
        sudo usermod -aG docker $USER
        log_success "Added $USER to docker group (logout required)"
      fi
      
      log_success "Development environment installed"
      ;;
      
    generic)
      log_info "Generic profile - no additional packages"
      ;;
  esac
  
  save_checkpoint "PROFILE"
  check_temperature
fi

############################################################
# Directories and aliases
############################################################
if ! is_checkpoint_passed "ALIASES"; then
  log_info "Creating useful directories..."
  mkdir -p ~/projects ~/scripts ~/backup ~/logs
  
  log_info "Setting up useful aliases..."
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

EOF
    log_success "Aliases added to ~/.bashrc"
  else
    log_info "Aliases already exist in ~/.bashrc"
  fi

  log_info "Creating system info script..."
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
echo "SSH Status:    $(systemctl is-active ssh)"
echo "Firewall:      $(sudo ufw status | head -1)"
if [ -f ~/.rpi_setup_state ]; then
  echo "---"
  echo "Setup Profile: $(grep PROFILE= ~/.rpi_setup_state | cut -d= -f2)"
  echo "Setup Date:    $(grep INSTALL_DATE= ~/.rpi_setup_state | cut -d= -f2)"
fi
echo "=========================================="
EOF
  chmod +x ~/scripts/sysinfo.sh
  log_success "System info script created at ~/scripts/sysinfo.sh"

  # Performance tips for low-tier systems
  if [[ "$PERF_TIER" == "LOW" ]] || [[ "$PERF_TIER" == "MINIMAL" ]]; then
    log_info "Creating performance tips file for low-spec Pi..."
    cat > ~/LOW_SPEC_TIPS.txt <<'EOF'
=== Performance Tips for Low-Spec Raspberry Pi ===

Your Pi has limited resources. Here are some tips:

1. MEMORY MANAGEMENT
   - Check memory: free -h
   - Check swap: swapon --show
   - Kill processes: sudo killall <process-name>

2. AVOID HEAVY PACKAGES
   - Don't install: numpy, scipy, pandas, tensorflow (unless from piwheels)
   - Use lightweight alternatives when possible
   - Install only what you need

3. PIWHEELS - PRE-COMPILED PACKAGES
   - Already configured in ~/.pip/pip.conf
   - Provides ARM wheels for faster installation
   - Reduces compilation time from hours to minutes

4. SERVICE MANAGEMENT
   - Disable unused services: sudo systemctl disable <service>
   - Check running services: systemctl list-units --type=service --state=running
   - Stop services: sudo systemctl stop <service>

5. STORAGE
   - Use lightweight file systems
   - Regularly clean: sudo apt autoremove && sudo apt clean
   - Check disk space: df -h
   - Clear logs: sudo journalctl --vacuum-time=7d

6. OVERCLOCKING (Pi 1/Zero only - use with caution)
   - Edit /boot/config.txt or /boot/firmware/config.txt
   - Add: arm_freq=1000 (or appropriate for your model)
   - Monitor temperature: watch vcgencmd measure_temp
   - DO NOT exceed 1000MHz without proper cooling

7. HEADLESS OPERATION
   - Disable desktop environment if not needed
   - Use SSH instead of local desktop
   - Set GPU memory to minimum (16MB)

8. PROFILE SWITCHING
   - Rerun setup script to switch profiles
   - Current profile shown in: cat ~/.rpi_setup_state
   - Switch with: ./setup.sh

For more info: https://www.raspberrypi.org/documentation/
EOF
    log_success "Performance tips saved to ~/LOW_SPEC_TIPS.txt"
  fi

  save_checkpoint "ALIASES"
fi

############################################################
# Save final state
############################################################
save_state

############################################################
# Cleanup
############################################################
log_info "Cleaning up package cache..."
sudo apt-get autoremove -y
sudo apt-get autoclean

############################################################
# Mark as complete
############################################################
save_checkpoint "COMPLETE"
clear_checkpoint

############################################################
# Run system info reporter
############################################################
log_info "Running system information reporter..."
echo ""

if command -v curl &> /dev/null; then
  log_info "Fetching and running mml_rpi_info script..."
  
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
    # No email configured, use default or prompt
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
      log_info "Running system info report without email..."
      curl -fsSL https://raw.githubusercontent.com/mmlawless/mml_rpi_info/main/mml_rpi_info.sh | bash || \
        log_warning "System info report failed"
    else
      if prompt_yn "Send system info report via email? (y/n): " n; then
        report_email=$(read_tty "Enter email address for report: ")
        if [ -n "$report_email" ]; then
          if curl -fsSL https://raw.githubusercontent.com/mmlawless/mml_rpi_info/main/mml_rpi_info.sh | bash -s -- --email "$report_email"; then
            log_success "System info report sent to $report_email"
          else
            log_warning "System info report failed"
          fi
        else
          log_info "Skipping system info report"
        fi
      else
        log_info "Skipping system info report"
      fi
    fi
  fi
else
  log_warning "curl not available, skipping system info report"
fi

echo ""

############################################################
# Summary
############################################################
echo ""
echo "=========================================="
log_success "Raspberry Pi setup completed successfully!"
echo "=========================================="
echo "Configuration Summary:"
echo "  - Hostname: $NEW_HOSTNAME"
echo "  - Model: Raspberry Pi $PI_MODEL"
echo "  - Serial: $PI_SERIAL"
echo "  - Memory: ${PI_MEMORY}MB RAM"
echo "  - Performance Tier: $PERF_TIER"
echo "  - Architecture: $PI_ARCH"
echo "  - Profile: $PROFILE ($PROFILE_ABBREV)"
echo ""
echo "What was installed:"
echo "  - System packages updated and upgraded"
echo "  - Filesystem expanded"
echo "  - Essential tools installed (tier-appropriate)"
echo "  - Basic firewall (UFW) configured"
echo "  - SSH enabled"
if [[ "$PERF_TIER" != "MINIMAL" ]]; then
  echo "  - Python packages installed (tier-appropriate)"
  echo "  - Piwheels configured for faster Python installs"
fi
echo "  - Profile packages: $PROFILE"
echo "  - Directories created: ~/projects, ~/scripts, ~/backup, ~/logs"
echo "  - Bash aliases added"
echo "  - System info script: ~/scripts/sysinfo.sh"
if [ -f ~/.msmtprc ]; then
  echo "  - Email (msmtp) configured"
fi
if [[ "$PERF_TIER" == "LOW" ]] || [[ "$PERF_TIER" == "MINIMAL" ]]; then
  echo "  - Performance tips: ~/LOW_SPEC_TIPS.txt"
fi
echo ""
echo "Useful commands:"
echo "  sysinfo           - Show system information"
echo "  profile           - Show current setup profile"
echo "  temp              - Show CPU temperature"
echo "  update            - Update and upgrade packages"
echo ""
echo "Profile switching:"
echo "  To switch profiles, run this script again"
echo "  It will detect the previous installation and offer profile switching"
echo ""

if [[ "$PERF_TIER" == "LOW" ]] || [[ "$PERF_TIER" == "MINIMAL" ]]; then
  log_warning "TIP: Read ~/LOW_SPEC_TIPS.txt for performance optimization"
fi

log_warning "IMPORTANT: Reboot required to finalize all changes"
log_info "New hostname ($NEW_HOSTNAME) will be active after reboot"
echo ""

if prompt_yn "Would you like to reboot now? (y/n): " n; then
  log_info "Rebooting in 5 seconds... (Ctrl+C to cancel)"
  sleep 5
  sudo reboot
else
  log_info "Please remember to reboot when convenient: sudo reboot"
  if [[ "$PERF_TIER" == "LOW" ]] || [[ "$PERF_TIER" == "MINIMAL" ]]; then
    log_info "After reboot, consider reducing GPU memory in /boot/config.txt to 16MB"
  fi
  echo ""
  log_success "Setup complete! Enjoy your Raspberry Pi!"
fi
