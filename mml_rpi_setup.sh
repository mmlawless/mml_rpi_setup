#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures

############################################################
# --- Self-heal CRLF and support curl | bash execution ---
############################################################
fix_and_reexec() {
  local tmp
  tmp="$(mktemp)"
  tr -d '\r' < "$1" > "$tmp"
  chmod +x "$tmp"
  exec /bin/bash "$tmp" "$@"
}

# If this script is an actual file and has CRLF → fix + re-run
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -r "${BASH_SOURCE[0]}" ]; then
  if grep -q $'\r' "${BASH_SOURCE[0]}" 2>/dev/null; then
    echo "[INFO] Converting CRLF → LF (file) and re-running..."
    fix_and_reexec "${BASH_SOURCE[0]}" "$@"
  fi
fi

# If piped from curl and stdin contains CRLF → fix + re-run
if [ ! -r "${BASH_SOURCE[0]:-}" ] && ! [ -t 0 ]; then
  if grep -q $'\r' /proc/$$/fd/0 2>/dev/null; then
    echo "[INFO] Converting CRLF → LF (stdin) and re-running..."
    local tmp_in
    tmp_in="$(mktemp)"
    cat - > "$tmp_in"
    fix_and_reexec "$tmp_in" "$@"
  fi
fi

############################################################
# --- Locale fix ---
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
# --- Utilities and colour setup ---
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
    log_info "Non-interactive mode: defaulting '$question' → $default"
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

# Check if running on Raspberry Pi
if [ ! -f /proc/device-tree/model ] || ! grep -q "Raspberry Pi" /proc/device-tree/model 2>/dev/null; then
  log_warning "This doesn't appear to be a Raspberry Pi"
  if ! prompt_yn "Continue anyway? (y/n): " n; then
    log_info "Setup cancelled"
    exit 0
  fi
fi

############################################################
# --- Main banner ---
############################################################
echo "=========================================="
echo "Raspberry Pi Initial Setup Script"
echo "Version: 2024-10-15"
echo "=========================================="
echo ""

setup_locale

############################################################
# --- System update & essentials ---
############################################################
log_info "Updating package lists..."
if ! sudo apt-get update -y; then
  log_error "Failed to update package lists"
  exit 1
fi

log_info "Upgrading installed packages (this may take a while)..."
if ! sudo apt-get upgrade -y; then
  log_error "Failed to upgrade packages"
  exit 1
fi

log_info "Installing essential packages..."
ESSENTIAL_PACKAGES=(
  curl wget git vim htop tree unzip
  build-essential python3-pip python3-venv
  nodejs npm apt-transport-https ca-certificates
  gnupg lsb-release net-tools ufw
)

if ! sudo apt-get install -y "${ESSENTIAL_PACKAGES[@]}"; then
  log_error "Failed to install essential packages"
  exit 1
fi

log_success "Essential packages installed"

############################################################
# --- Basic Security Setup ---
############################################################
log_info "Setting up basic firewall (UFW)..."
sudo ufw --force enable
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
log_success "Firewall configured (SSH allowed)"

############################################################
# --- Enable SSH ---
############################################################
if ! systemctl is-active --quiet ssh; then
  log_info "Enabling SSH service..."
  sudo systemctl enable --now ssh
  log_success "SSH service enabled and started"
else
  log_info "SSH service already running"
fi

############################################################
# --- Optional Git setup ---
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
# --- Filesystem & interfaces ---
############################################################
if command -v raspi-config &> /dev/null; then
  log_info "Expanding filesystem to use full SD card..."
  if sudo raspi-config nonint do_expand_rootfs; then
    log_success "Filesystem expansion configured (takes effect after reboot)"
  else
    log_warning "Filesystem expansion may have already been performed"
  fi

  if prompt_yn "Allocate 128 MB GPU memory? (y/n): " n; then
    if ! grep -q "^gpu_mem=" /boot/config.txt 2>/dev/null && ! grep -q "^gpu_mem=" /boot/firmware/config.txt 2>/dev/null; then
      # Check which config file exists (newer Pi OS uses /boot/firmware)
      if [ -f /boot/firmware/config.txt ]; then
        echo "gpu_mem=128" | sudo tee -a /boot/firmware/config.txt > /dev/null
      else
        echo "gpu_mem=128" | sudo tee -a /boot/config.txt > /dev/null
      fi
      log_success "GPU memory set to 128 MB (requires reboot)"
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
# --- Python packages ---
############################################################
log_info "Installing common Python packages..."
PYTHON_PACKAGES=(
  numpy matplotlib requests flask
  RPi.GPIO adafruit-circuitpython-motor
  adafruit-circuitpython-servo
)

# Install in user space to avoid conflicts
if pip3 install --user --no-warn-script-location "${PYTHON_PACKAGES[@]}"; then
  log_success "Python packages installed"
  
  # Add user Python bin to PATH if not already there
  if ! grep -q 'export PATH="$HOME/.local/bin:$PATH"' ~/.bashrc; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
  fi
else
  log_warning "Some Python packages may have failed to install"
fi

############################################################
# --- Directories, aliases, scripts ---
############################################################
log_info "Creating useful directories..."
mkdir -p ~/projects ~/scripts ~/backup

log_info "Setting up useful aliases..."
# Check if aliases already exist to avoid duplication
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
echo "OS:            $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "Kernel:        $(uname -r)"
echo "Architecture:  $(uname -m)"
echo "Uptime:        $(uptime -p)"
echo "Temperature:   $(vcgencmd measure_temp 2>/dev/null || echo 'N/A')"
echo "Memory Usage:  $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
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
# --- Cleanup ---
############################################################
log_info "Cleaning up package cache..."
sudo apt-get autoremove -y
sudo apt-get autoclean

############################################################
# --- Summary ---
############################################################
echo ""
echo "=========================================="
log_success "Raspberry Pi setup completed successfully!"
echo "=========================================="
echo "Summary:"
echo "✓ System packages updated and upgraded"
echo "✓ Filesystem expanded"
echo "✓ Essential development tools installed"
echo "✓ Basic firewall (UFW) configured"
echo "✓ SSH enabled"
echo "✓ Python packages installed"
echo "✓ Directories created: ~/projects, ~/scripts, ~/backup"
echo "✓ Bash aliases added"
echo "✓ System info script: ~/scripts/sysinfo.sh"
echo ""
log_warning "IMPORTANT: Reboot required to finalize all changes"
echo ""

if prompt_yn "Would you like to reboot now? (y/n): " n; then
  log_info "Rebooting in 5 seconds... (Ctrl+C to cancel)"
  sleep 5
  sudo reboot
else
  log_info "Please remember to reboot when convenient: sudo reboot"
fi
