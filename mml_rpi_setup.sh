#!/bin/bash
set -euo pipefail

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

# If this script is an actual file and has CRLF, fix and re-run
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
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1" >&2; }

# Detect interactive terminal
IS_TTY=0
[ -t 0 ] && IS_TTY=1

prompt_yn() {
  local question="$1" default="${2:-n}" ans
  if [ "$IS_TTY" -eq 1 ]; then
    read -r -p "$question" ans < /dev/tty || ans="$default"
  else
    log_info "Non-interactive mode: defaulting '$question' to $default"
    ans="$default"
  fi
  [[ "$ans" =~ ^[Yy]$ ]]
}

read_tty() {
  local prompt="$1" var
  if [ "$IS_TTY" -eq 1 ]; then
    read -r -p "$prompt" var < /dev/tty
    echo "$var"
  else
    echo ""
  fi
}

# Check if running as root (should not be)
if [ "$EUID" -eq 0 ]; then 
  log_error "Please do not run this script as root or with sudo"
  log_error "The script will prompt for sudo when needed"
  exit 1
fi

############################################################
# Detect Pi model and memory
############################################################
detect_pi_info() {
  PI_MODEL="unknown"
  PI_MEMORY=0
  PI_ARCH="unknown"
  
  # Detect architecture
  PI_ARCH=$(uname -m)
  
  # Try to detect from device tree
  if [ -f /proc/device-tree/model ]; then
    MODEL_STRING=$(cat /proc/device-tree/model 2>/dev/null | tr -d '\0')
    
    case "$MODEL_STRING" in
      *"Pi Zero"*|*"Pi 0"*)
        PI_MODEL="0"
        ;;
      *"Compute Module"*)
        # Extract version number if present
        if [[ "$MODEL_STRING" =~ "Compute Module 4" ]]; then
          PI_MODEL="CM4"
        elif [[ "$MODEL_STRING" =~ "Compute Module 3" ]]; then
          PI_MODEL="CM3"
        else
          PI_MODEL="CM"
        fi
        ;;
      *"Pi 5"*)
        PI_MODEL="5"
        ;;
      *"Pi 4"*)
        PI_MODEL="4"
        ;;
      *"Pi 3"*)
        PI_MODEL="3"
        ;;
      *"Pi 2"*)
        PI_MODEL="2"
        ;;
      *"Pi 1"*|*"Model B Rev"*)
        PI_MODEL="1"
        ;;
    esac
  fi
  
  # Detect memory
  if [ -f /proc/meminfo ]; then
    MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    PI_MEMORY=$((MEM_KB / 1024))
  fi
  
  log_info "Detected: Raspberry Pi Model $PI_MODEL, ${PI_MEMORY}MB RAM, $PI_ARCH architecture"
}

############################################################
# Pi Model Selection
############################################################
select_pi_model() {
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
    1)
      PI_MODEL="0"
      PI_MEMORY=512
      PI_ARCH="armv6l"
      ;;
    2)
      PI_MODEL="1"
      local mem_choice
      mem_choice=$(read_tty "Memory size? [256/512] (default: 512): ")
      PI_MEMORY=${mem_choice:-512}
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
      mem_choice=$(read_tty "Memory size? [1024/2048/4096/8192] (default: 2048): ")
      PI_MEMORY=${mem_choice:-2048}
      PI_ARCH="armv8"
      ;;
    6)
      log_info "Using auto-detected values"
      ;;
    7)
      PI_MODEL=$(read_tty "Enter Pi model (0/1/2/3/4/5): ")
      PI_MEMORY=$(read_tty "Enter RAM in MB: ")
      PI_ARCH=$(read_tty "Enter architecture (armv6l/armv7l/armv8): ")
      ;;
    *)
      log_warning "Invalid choice, using auto-detected values"
      ;;
  esac
  
  # Set performance tier based on model and memory
  set_performance_tier
  
  echo ""
  log_info "Configuration: Pi $PI_MODEL, ${PI_MEMORY}MB RAM, $PI_ARCH"
  log_info "Performance tier: $PERF_TIER"
  echo ""
}

############################################################
# Performance Tier Configuration
############################################################
set_performance_tier() {
  # LOW: Pi 0, Pi 1 with ≤512MB
  # MEDIUM: Pi 2, Pi 3, Pi 1 with >512MB
  # HIGH: Pi 4, Pi 5
  
  if [[ "$PI_MODEL" == "4" ]] || [[ "$PI_MODEL" == "5" ]]; then
    PERF_TIER="HIGH"
  elif [[ "$PI_MODEL" == "2" ]] || [[ "$PI_MODEL" == "3" ]]; then
    PERF_TIER="MEDIUM"
  elif [ "$PI_MEMORY" -le 512 ]; then
    PERF_TIER="LOW"
  else
    PERF_TIER="MEDIUM"
  fi
  
  # Override for very low memory
  if [ "$PI_MEMORY" -le 256 ]; then
    PERF_TIER="MINIMAL"
  fi
}

############################################################
# Check and setup swap for low memory systems
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
        
        # Disable existing swap
        sudo dphys-swapfile swapoff 2>/dev/null || true
        
        # Configure swap size
        sudo sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=1024/' /etc/dphys-swapfile 2>/dev/null || \
          echo "CONF_SWAPSIZE=1024" | sudo tee -a /etc/dphys-swapfile > /dev/null
        
        # Setup and enable new swap
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
# Main banner
############################################################
echo "=========================================="
echo "Universal Raspberry Pi Setup Script"
echo "Version: 2024-10-20"
echo "=========================================="
echo ""

# Detect and select Pi model
detect_pi_info

# Check if running on Raspberry Pi
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
setup_locale

############################################################
# Setup swap for low-memory systems
############################################################
if [[ "$PERF_TIER" == "LOW" ]] || [[ "$PERF_TIER" == "MINIMAL" ]]; then
  setup_swap
fi

############################################################
# System update & essentials
############################################################
log_info "Updating package lists..."
if ! sudo apt-get update -y; then
  log_error "Failed to update package lists"
  exit 1
fi

if [[ "$PERF_TIER" == "MINIMAL" ]]; then
  log_warning "Very low memory detected. Upgrade will be slow and may take hours."
  if ! prompt_yn "Proceed with full system upgrade? (y/n): " y; then
    log_info "Skipping upgrade. You can run 'sudo apt upgrade' manually later."
  else
    log_info "Upgrading packages (this will take a LONG time on low-spec Pi)..."
    sudo apt-get upgrade -y
  fi
else
  log_info "Upgrading installed packages (this may take a while)..."
  if [[ "$PERF_TIER" == "LOW" ]]; then
    log_warning "This may take 30-60 minutes on older Pi models..."
  fi
  if ! sudo apt-get upgrade -y; then
    log_error "Failed to upgrade packages"
    exit 1
  fi
fi

############################################################
# Essential packages (optimized by tier)
############################################################
log_info "Installing essential packages for $PERF_TIER tier system..."

# Base packages for all systems
ESSENTIAL_PACKAGES=(
  curl wget git vim htop tree unzip
  apt-transport-https ca-certificates
  gnupg lsb-release net-tools ufw
)

# Add build tools based on performance tier
if [[ "$PERF_TIER" != "MINIMAL" ]]; then
  ESSENTIAL_PACKAGES+=(build-essential)
fi

# Add Python based on tier
if [[ "$PERF_TIER" == "HIGH" ]] || [[ "$PERF_TIER" == "MEDIUM" ]]; then
  ESSENTIAL_PACKAGES+=(python3-pip python3-venv python3-dev)
elif [[ "$PERF_TIER" == "LOW" ]]; then
  ESSENTIAL_PACKAGES+=(python3-pip python3-venv)
else
  # MINIMAL: only basic python
  ESSENTIAL_PACKAGES+=(python3)
fi

# Node.js only for medium/high tier with compatible architecture
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

############################################################
# Basic Security Setup
############################################################
log_info "Setting up basic firewall (UFW)..."
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
log_success "Firewall configured (SSH allowed)"

############################################################
# Enable SSH
############################################################
if ! systemctl is-active --quiet ssh; then
  log_info "Enabling SSH service..."
  sudo systemctl enable --now ssh
  log_success "SSH service enabled and started"
else
  log_info "SSH service already running"
fi

############################################################
# Optional Git setup
############################################################
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

############################################################
# Optional Email (msmtp) setup
############################################################
if [ -f ~/.msmtprc ]; then
  log_info "Email (msmtp) already configured"
  if prompt_yn "Would you like to reconfigure email? (y/n): " n; then
    rm ~/.msmtprc
  else
    log_info "Skipping email configuration"
  fi
fi

if [ ! -f ~/.msmtprc ]; then
  if prompt_yn "Would you like to configure email (msmtp)? (y/n): " n; then
    log_info "Installing msmtp..."
    sudo apt-get install -y msmtp msmtp-mta
    
    if [ $? -eq 0 ]; then
      email_address=$(read_tty "Enter your Gmail address: ")
      
      if [ -n "$email_address" ]; then
        log_warning "You need a Gmail App Password (not your regular password)"
        log_info "Create one at: https://myaccount.google.com/apppasswords"
        app_password=$(read_tty "Enter your Gmail App Password (16 characters, no spaces): ")
        
        if [ -n "$app_password" ]; then
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
from           ${email_address}
user           ${email_address}
password       ${app_password}

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
    else
      log_error "Failed to install msmtp"
    fi
  fi
fi

############################################################
# Filesystem & interfaces
############################################################
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

############################################################
# Python packages (tier-based)
############################################################
if [[ "$PERF_TIER" != "MINIMAL" ]]; then
  if prompt_yn "Install Python packages? (y/n): " y; then
    log_info "Installing Python packages for $PERF_TIER tier system..."
    
    PYTHON_PACKAGES=()
    
    # Minimal packages for LOW tier
    if [[ "$PERF_TIER" == "LOW" ]]; then
      log_warning "Installing only lightweight Python packages for low-spec Pi"
      PYTHON_PACKAGES=(
        requests
        RPi.GPIO
      )
      
      if prompt_yn "Install Flask (web framework)? May be slow (y/n): " n; then
        PYTHON_PACKAGES+=(flask)
      fi
      
    # Medium packages
    elif [[ "$PERF_TIER" == "MEDIUM" ]]; then
      PYTHON_PACKAGES=(
        requests flask
        RPi.GPIO
      )
      
      if prompt_yn "Install scientific packages (numpy)? Compilation may take 15-30 min (y/n): " n; then
        PYTHON_PACKAGES+=(numpy)
      fi
      
      if prompt_yn "Install Adafruit libraries? (y/n): " n; then
        PYTHON_PACKAGES+=(
          adafruit-circuitpython-motor
          adafruit-circuitpython-servo
        )
      fi
      
    # Full packages for HIGH tier
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
      
      if [[ "$PERF_TIER" == "LOW" ]]; then
        log_warning "Installation may take 10-30 minutes on low-spec Pi..."
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

############################################################
# Directories, aliases, scripts
############################################################
log_info "Creating useful directories..."
mkdir -p ~/projects ~/scripts ~/backup

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
echo "=========================================="
EOF
chmod +x ~/scripts/sysinfo.sh
log_success "System info script created at ~/scripts/sysinfo.sh"

############################################################
# Performance tips for low-tier systems
############################################################
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
   - Don't install: numpy, scipy, pandas, tensorflow
   - Use lightweight alternatives when possible
   - Install only what you need

3. COMPILATION
   - Compiling Python packages can take hours
   - Consider using pre-compiled wheels from piwheels
   - Add to ~/.pip/pip.conf:
     [global]
     extra-index-url=https://www.piwheels.org/simple

4. SERVICE MANAGEMENT
   - Disable unused services: sudo systemctl disable <service>
   - Check running services: systemctl list-units --type=service --state=running

5. STORAGE
   - Use lightweight file systems
   - Regularly clean: sudo apt autoremove && sudo apt clean
   - Check disk space: df -h

6. OVERCLOCKING (Pi 1/Zero only - use with caution)
   - Edit /boot/config.txt
   - Add: arm_freq=1000 (or appropriate for your model)
   - Monitor temperature: watch vcgencmd measure_temp

7. HEADLESS OPERATION
   - Disable desktop environment if not needed
   - Use SSH instead of local desktop
   - Set GPU memory to minimum (16MB)

For more info: https://www.raspberrypi.org/documentation/
EOF
  log_success "Performance tips saved to ~/LOW_SPEC_TIPS.txt"
fi

############################################################
# Cleanup
############################################################
log_info "Cleaning up package cache..."
sudo apt-get autoremove -y
sudo apt-get autoclean

############################################################
# Summary
############################################################
echo ""
echo "=========================================="
log_success "Raspberry Pi setup completed successfully!"
echo "=========================================="
echo "Configuration Summary:"
echo "  - Model: Raspberry Pi $PI_MODEL"
echo "  - Memory: ${PI_MEMORY}MB RAM"
echo "  - Performance Tier: $PERF_TIER"
echo "  - Architecture: $PI_ARCH"
echo ""
echo "What was installed:"
echo "  - System packages updated"
echo "  - Filesystem expanded"
echo "  - Essential tools installed (tier-appropriate)"
echo "  - Basic firewall (UFW) configured"
echo "  - SSH enabled"
if [[ "$PERF_TIER" != "MINIMAL" ]]; then
  echo "  - Python packages installed (tier-appropriate)"
fi
echo "  - Directories created: ~/projects, ~/scripts, ~/backup"
echo "  - Bash aliases added"
echo "  - System info script: ~/scripts/sysinfo.sh"
if [ -f ~/.msmtprc ]; then
  echo "  - Email (msmtp) configured"
fi
if [[ "$PERF_TIER" == "LOW" ]] || [[ "$PERF_TIER" == "MINIMAL" ]]; then
  echo "  - Performance tips: ~/LOW_SPEC_TIPS.txt"
fi
echo ""

if [[ "$PERF_TIER" == "LOW" ]] || [[ "$PERF_TIER" == "MINIMAL" ]]; then
  log_warning "TIP: Read ~/LOW_SPEC_TIPS.txt for performance optimization"
fi

log_warning "IMPORTANT: Reboot required to finalize all changes"
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
fi
