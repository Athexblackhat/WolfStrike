#!/data/data/com.termux/files/usr/bin/bash
# ============================================================
# WOLFSTRIKE Termux Setup Script
# Author: ATHEX BLACK HAT
# Team: Wolf Intelligence PK
# Version: 1.0.0
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

INSTALL_DIR="$HOME/wolfstrike"
CONFIG_DIR="$HOME/.config/wolfstrike"

echo -e "${CYAN}"
echo "============================================================"
echo "  WOLFSTRIKE v1.0.0 - Termux Setup"
echo "  Wolf Intelligence PK | ATHEX BLACK HAT"
echo "============================================================"
echo -e "${NC}"

echo -e "${BLUE}[*] Checking Termux environment...${NC}"

if [[ ! -d "/data/data/com.termux" ]] && [[ -z "$PREFIX" ]]; then
    echo -e "${RED}[-] This script is for Termux only${NC}"
    echo -e "${YELLOW}[!] For Linux, use install.sh${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Termux environment detected${NC}"

echo -e "${BLUE}[*] Updating package lists...${NC}"
pkg update -y -qq

echo -e "${BLUE}[*] Upgrading packages...${NC}"
pkg upgrade -y -qq

echo -e "${BLUE}[*] Installing core dependencies...${NC}"
pkg install -y \
    python \
    python-pip \
    git \
    curl \
    wget \
    openssl \
    libxml2 \
    libxslt \
    clang \
    make \
    cmake \
    2>/dev/null || true

echo -e "${GREEN}[+] Core dependencies installed${NC}"

echo -e "${BLUE}[*] Installing optional tools...${NC}"
pkg install -y \
    nmap \
    dnsutils \
    whois \
    2>/dev/null || true

echo -e "${GREEN}[+] Optional tools installed${NC}"

echo -e "${BLUE}[*] Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$INSTALL_DIR/logs"
mkdir -p "$INSTALL_DIR/reports"

echo -e "${GREEN}[+] Directories created${NC}"

echo -e "${BLUE}[*] Installing Python packages...${NC}"
pip install --upgrade pip setuptools wheel -q

pip install \
    requests \
    beautifulsoup4 \
    dnspython \
    rich \
    PyYAML \
    urllib3 \
    certifi \
    colorama \
    tqdm \
    -q 2>/dev/null || true

echo -e "${GREEN}[+] Python packages installed${NC}"

echo -e "${BLUE}[*] Creating launcher script...${NC}"

LAUNCHER="$PREFIX/bin/wolfstrike"

cat > "$LAUNCHER" << 'LAUNCHEREOF'
#!/data/data/com.termux/files/usr/bin/bash
cd $HOME/wolfstrike
python wolfstrike.py "$@"
LAUNCHEREOF

chmod +x "$LAUNCHER"

echo -e "${GREEN}[+] Launcher created: wolfstrike${NC}"

echo -e "${BLUE}[*] Setting up bash alias...${NC}"

if ! grep -q "alias wolfstrike=" "$HOME/.bashrc" 2>/dev/null; then
    echo "alias wolfstrike='python $HOME/wolfstrike/wolfstrike.py'" >> "$HOME/.bashrc"
    echo -e "${GREEN}[+] Alias added to .bashrc${NC}"
fi

echo ""
echo -e "${CYAN}============================================================${NC}"
echo -e "${GREEN}  WOLFSTRIKE Termux Setup Complete!${NC}"
echo -e "${CYAN}============================================================${NC}"
echo ""
echo -e "  Installation Directory: ${YELLOW}$INSTALL_DIR${NC}"
echo -e "  Configuration:          ${YELLOW}$CONFIG_DIR${NC}"
echo ""
echo -e "  Quick Start:"
echo -e "    ${GREEN}wolfstrike --target example.com${NC}"
echo -e "    ${GREEN}wolfstrike --interactive${NC}"
echo -e "    ${GREEN}wolfstrike --help${NC}"
echo ""
echo -e "  ${YELLOW}NOTE: Restart Termux or run: source ~/.bashrc${NC}"
echo ""
echo -e "  ${RED}WARNING: Termux version has limited features.${NC}"
echo -e "  ${RED}For full power, use Kali Linux or Docker.${NC}"
echo ""
echo -e "  ${BLUE}Wolf Intelligence PK | ATHEX BLACK HAT${NC}"
echo ""