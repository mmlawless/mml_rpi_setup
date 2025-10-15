#!/bin/bash
set -e  # Exit on any error

# --- Self-heal Windows CRLF line endings and re-exec ---
if grep -q $'\r' "$0"; then
  echo "[INFO] Converting CRLF -> LF and re-running…"
  tmp="$(mktemp)"
  tr -d '\r' < "$0" > "$tmp"
  chmod +x "$tmp"
  exec /bin/bash "$tmp" "$@"
fi

echo "=========================================="
echo "Raspberry Pi Initial Setup Script 151025"
echo "=========================================="

# Ensure locales exist (idempotent)
if ! locale -a 2>/dev/null | grep -qi '^en_GB\.utf8$'; then
  sudo apt-get update
  sudo apt-get install -y locales
  sudo sed -i 's/^# *en_GB.UTF-8 UTF-8/en_GB.UTF-8 UTF-8/' /etc/locale.gen
  sudo locale-gen
  sudo update-locale LANG=en_GB.UTF-8
fi
export LANG=en_GB.UTF-8
export LC_ALL=en_GB.UTF-8

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $1"; }

# Function to check if command exists
command_exists() { command -v "$1" >/dev/null 2>&1; }

# Update system packages
log_info "Updating package lists..."
sudo apt update

log_info "Upgrading installed packages..."
sudo apt upgrade -y

log_info "Installing essential packages..."
sudo apt install -y \
  curl \
  wget \
  git \
  vim \
  htop \
  tree \
  unzip \
  build-essential \
  python3-pip \
  python3-venv \
  nodejs \
  npm \
  apt \
  ca-certificates \
  gnupg \
  lsb-release \
  net-tools

# Enable SSH (if not already enabled)
log_info "Enabling SSH service..."
sudo systemctl enable --now ssh

# Configure Git (optional - you can customize these)
read -p "Would you like to configure Git? (y/n): " configure_git
if [[ "$configure_git" =~ ^[Yy]$ ]]; then
    read -p "Enter your Git username: " git_username
    read -p "Enter your Git email: " git_email
    git config --global user.name "$git_username"
    git config --global user.email "$git_email"
    log_success "Git configured successfully"
fi

# Expand filesystem to use full SD card
log_info "Expanding filesystem to use full SD card..."
sudo raspi-config nonint do_expand_rootfs
log_success "Filesystem expansion configured (will take effect after reboot)"

# Configure memory split for GPU (useful for camera/display work)
read -p "Would you like to allocate more memory to GPU? (useful for camera/display work) (y/n): " configure_gpu
if [[ "$configure_gpu" =~ ^[Yy]$ ]]; then
    echo "gpu_mem=128" | sudo tee -a /boot/config.txt
    log_success "GPU memory set to 128MB (requires reboot)"
fi

# Enable interfaces individually
read -p "Would you like to enable I2C interface? (y/n): " enable_i2c
if [[ "$enable_i2c" =~ ^[Yy]$ ]]; then
    sudo raspi-config nonint do_i2c 0
    log_success "I2C interface enabled"
fi

read -p "Would you like to enable SPI interface? (y/n): " enable_spi
if [[ "$enable_spi" =~ ^[Yy]$ ]]; then
    sudo raspi-config nonint do_spi 0
    log_success "SPI interface enabled"
fi

read -p "Would you like to enable Camera interface? (y/n): " enable_camera
if [[ "$enable_camera" =~ ^[Yy]$ ]]; then
    sudo raspi-config nonint do_camera 0
    log_success "Camera interface enabled"
fi

# Install Python packages commonly used in Pi projects
log_info "Installing common Python packages..."
pip3 install --user \
    numpy \
    matplotlib \
    requests \
    flask \
    RPi.GPIO \
    adafruit-circuitpython-motor \
    adafruit-circuitpython-servo

# Create useful directories
log_info "Creating useful directories..."
mkdir -p ~/projects ~/scripts ~/backup

# Set up aliases and bash improvements
log_info "Setting up useful aliases..."
cat >> ~/.bashrc << 'EOF'

# Custom aliases
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

# Git aliases
alias gs='git status'
alias ga='git add'
alias gc='git commit -m'
alias gp='git push'
alias gl='git log --oneline'

# System monitoring
alias processes='ps aux | head -20'
alias ports='netstat -tuln'

EOF

# Create a system info script
log_info "Creating system info script..."
cat > ~/scripts/sysinfo.sh << 'EOF'
#!/bin/bash
echo "=== Raspberry Pi System Information ==="
echo "Hostname: $(hostname)"
echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p)"
echo "Temperature: $(vcgencmd measure_temp)"
echo "Memory Usage: $(free -h | awk '/^Mem:/ {print $3 "/" $2}')"
echo "Disk Usage: $(df -h / | awk '/\// {print $3 "/" $2 " (" $5 ")"}')"
echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
echo "IP Address: $(hostname -I | awk '{print $1}')"
EOF
chmod +x ~/scripts/sysinfo.sh

# Clean up
log_info "Cleaning up package cache..."
sudo apt autoremove -y
sudo apt autoclean

# Final summary
echo ""
echo "=========================================="
log_success "Raspberry Pi setup completed successfully!"
echo "=========================================="
echo ""
echo "Summary of what was installed/configured:"
echo "• System packages updated and upgraded"
echo "• Filesystem expanded to use full SD card"
echo "• Essential development tools installed"
echo "• SSH service enabled"
echo "• Python packages for Pi projects installed"
echo "• Useful directories created (~/projects, ~/scripts, ~/backup)"
echo "• Bash aliases and improvements added"
echo "• System info script created (~/scripts/sysinfo.sh)"
if [[ "$configure_gpu" =~ ^[Yy]$ ]]; then
    echo "• GPU memory allocation configured"
fi
echo ""
echo "Next steps:"
echo "• Reboot your Pi: sudo reboot"
echo "• Run system info: ~/scripts/sysinfo.sh"
echo "• Check your IP: hostname -I"
echo ""
log_warning "A reboot is required to complete the setup (especially for filesystem expansion and interface changes)."
