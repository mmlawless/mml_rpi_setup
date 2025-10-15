#!/bin/bash
set -e  # Exit on any error

############################################################
# --- Self-heal CRLF and support curl | bash execution ---
############################################################
fix_and_reexec() {
  tmp="$(mktemp)"
  tr -d '\r' < "$1" > "$tmp"
  chmod +x "$tmp"
  exec /bin/bash "$tmp" "$@"
}

# If this script is an actual file and has CRLF → fix + re-run
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -r "${BASH_SOURCE[0]}" ] && grep -q $'\r' "${BASH_SOURCE[0]}"; then
  echo "[INFO] Converting CRLF → LF (file) and re-running..."
  fix_and_reexec "${BASH_SOURCE[0]}" "$@"
fi

# If piped from curl and stdin contains CRLF → fix + re-run
if [ ! -r "${BASH_SOURCE[0]:-}" ] && ! [ -t 0 ]; then
  if grep -q $'\r' /proc/$$/fd/0 2>/dev/null; then
    echo "[INFO] Converting CRLF → LF (stdin) and re-running..."
    tmp_in="$(mktemp)"
    cat - > "$tmp_in"
    fix_and_reexec "$tmp_in" "$@"
  fi
fi

############################################################
# --- Locale fix ---
############################################################
if ! locale -a 2>/dev/null | grep -qi '^en_GB\.utf8$'; then
  sudo apt-get update -y
  sudo apt-get install -y locales
  sudo sed -i 's/^# *en_GB.UTF-8 UTF-8/en_GB.UTF-8 UTF-8/' /etc/locale.gen
  sudo locale-gen
  sudo update-locale LANG=en_GB.UTF-8
fi
export LANG=en_GB.UTF-8
export LC_ALL=en_GB.UTF-8

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

# detect interactive terminal
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

############################################################
# --- Main banner ---
############################################################
echo "=========================================="
echo "Raspberry Pi Initial Setup Script 15-10-25"
echo "=========================================="

############################################################
# --- System update & essentials ---
############################################################
log_info "Updating package lists..."
sudo apt update -y

log_info "Upgrading installed packages..."
sudo apt upgrade -y

log_info "Installing essential packages..."
sudo apt install -y \
  curl wget git vim htop tree unzip build-essential \
  python3-pip python3-venv nodejs npm apt ca-certificates \
  gnupg lsb-release net-tools

############################################################
# --- Enable SSH ---
############################################################
log_info "Enabling SSH service..."
sudo systemctl enable --now ssh

############################################################
# --- Optional Git setup ---
############################################################
if prompt_yn "Would you like to configure Git? (y/n): " n; then
  git_username=$(read_tty "Enter your Git username: ")
  git_email=$(read_tty "Enter your Git email: ")
  git config --global user.name "$git_username"
  git config --global user.email "$git_email"
  log_success "Git configured successfully"
fi

############################################################
# --- Filesystem & interfaces ---
############################################################
log_info "Expanding filesystem to use full SD card..."
sudo raspi-config nonint do_expand_rootfs
log_success "Filesystem expansion configured (takes effect after reboot)"

if prompt_yn "Allocate 128 MB GPU memory? (y/n): " n; then
  echo "gpu_mem=128" | sudo tee -a /boot/config.txt
  log_success "GPU memory set to 128 MB (requires reboot)"
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

############################################################
# --- Python packages ---
############################################################
log_info "Installing common Python packages..."
pip3 install --user \
  numpy matplotlib requests flask RPi.GPIO \
  adafruit-circuitpython-motor adafruit-circuitpython-servo

############################################################
# --- Directories, aliases, scripts ---
############################################################
log_info "Creating useful directories..."
mkdir -p ~/projects ~/scripts ~/backup

log_info "Setting up useful aliases..."
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
alias gl='git log --oneline'
alias processes='ps aux | head -20'
alias ports='netstat -tuln'

EOF

log_info "Creating system info script..."
cat > ~/scripts/sysinfo.sh <<'EOF'
#!/bin/bash
echo "=== Raspberry Pi System Information ==="
echo "Hostname: $(hostname)"
echo "OS: $(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"
echo "Temperature: $(vcgencmd measure_temp)"
echo "Memory Usage: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "Disk Usage: $(df -h / | awk '/\// {print $3 "/" $2 " (" $5 ")"}')"
echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
echo "IP Address: $(hostname -I | awk '{print $1}')"
EOF
chmod +x ~/scripts/sysinfo.sh

############################################################
# --- Cleanup ---
############################################################
log_info "Cleaning up package cache..."
sudo apt autoremove -y
sudo apt autoclean

############################################################
# --- Summary ---
############################################################
echo ""
echo "=========================================="
log_success "Raspberry Pi setup completed successfully!"
echo "=========================================="
echo "Summary:"
echo "• System packages updated and upgraded"
echo "• Filesystem expanded"
echo "• Essential development tools installed"
echo "• SSH enabled"
echo "• Python packages installed"
echo "• ~/projects, ~/scripts, ~/backup created"
echo "• Bash aliases added"
echo "• System info script: ~/scripts/sysinfo.sh"
echo ""
log_warning "Reboot required to finalize setup."
echo "Next: sudo reboot"
