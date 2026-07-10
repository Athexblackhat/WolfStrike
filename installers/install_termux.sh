#!/bin/bash
# ============================================================
# WOLFSTRIKE Termux Installer
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
DATA_DIR="$HOME/.local/share/wolfstrike"

echo -e "${CYAN}"
echo "============================================================"
echo "  WOLFSTRIKE v1.0.0 - Termux Installer"
echo "  Wolf Intelligence PK | ATHEX BLACK HAT"
echo "============================================================"
echo -e "${NC}"

check_termux() {
    if [[ -d "/data/data/com.termux" ]] || [[ -n "$PREFIX" ]]; then
        echo -e "${GREEN}[+] Termux environment detected${NC}"
        return 0
    else
        echo -e "${RED}[-] This installer is for Termux only${NC}"
        echo -e "${YELLOW}[!] For Linux, use install.sh${NC}"
        exit 1
    fi
}

install_termux_dependencies() {
    echo -e "${BLUE}[*] Installing Termux dependencies...${NC}"
    
    pkg update -y
    pkg upgrade -y
    
    pkg install -y \
        python \
        python-pip \
        git \
        nmap \
        dnsutils \
        whois \
        curl \
        wget \
        openssl \
        libxml2 \
        libxslt \
        clang \
        make \
        2>/dev/null || true
    
    echo -e "${GREEN}[+] Termux dependencies installed${NC}"
}

install_python_dependencies() {
    echo -e "${BLUE}[*] Installing Python dependencies (Termux)...${NC}"
    
    cd "$INSTALL_DIR"
    
    pip install --upgrade pip setuptools wheel
    
    if [[ -f "requirements_termux.txt" ]]; then
        pip install -r requirements_termux.txt
    elif [[ -f "requirements.txt" ]]; then
        echo -e "${YELLOW}[!] requirements_termux.txt not found, using requirements.txt${NC}"
        pip install -r requirements.txt 2>/dev/null || {
            echo -e "${YELLOW}[!] Full requirements failed, installing core dependencies...${NC}"
            pip install requests beautifulsoup4 dnspython rich PyYAML urllib3 certifi
        }
    else
        echo -e "${YELLOW}[!] Installing core dependencies...${NC}"
        pip install requests beautifulsoup4 dnspython rich PyYAML urllib3 certifi
    fi
    
    echo -e "${GREEN}[+] Python dependencies installed${NC}"
}

create_directories() {
    echo -e "${BLUE}[*] Creating directories...${NC}"
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DATA_DIR/logs"
    mkdir -p "$DATA_DIR/reports"
    
    echo -e "${GREEN}[+] Directories created${NC}"
}

create_launcher() {
    echo -e "${BLUE}[*] Creating launcher...${NC}"
    
    LAUNCHER="$PREFIX/bin/wolfstrike"
    
    cat > "$LAUNCHER" << 'EOF'
#!/bin/bash
cd $HOME/wolfstrike
python3 wolfstrike.py "$@"
EOF
    
    chmod +x "$LAUNCHER"
    echo -e "${GREEN}[+] Launcher created${NC}"
}

setup_bashrc() {
    echo -e "${BLUE}[*] Setting up bashrc alias...${NC}"
    
    if ! grep -q "alias wolfstrike=" "$HOME/.bashrc" 2>/dev/null; then
        echo "alias wolfstrike='python3 $INSTALL_DIR/wolfstrike.py'" >> "$HOME/.bashrc"
        echo -e "${GREEN}[+] Alias added to .bashrc${NC}"
    fi
}

print_warning() {
    echo ""
    echo -e "${YELLOW}============================================================${NC}"
    echo -e "${YELLOW}  TERMUX LIMITATION NOTICE${NC}"
    echo -e "${YELLOW}============================================================${NC}"
    echo ""
    echo -e "  You are running WOLFSTRIKE on Termux (Android)."
    echo -e ""
    echo -e "  ${GREEN}ENABLED FEATURES:${NC}"
    echo -e "    - Basic Scanning"
    echo -e "    - Reconnaissance"
    echo -e "    - Vulnerability Detection"
    echo -e "    - Port Scanning (limited)"
    echo -e ""
    echo -e "  ${RED}DISABLED FEATURES:${NC}"
    echo -e "    - Advanced Attack Modules"
    echo -e "    - AI Engine (Full Power)"
    echo -e "    - Multi-threading (Limited)"
    echo -e "    - Browser Automation"
    echo -e "    - Raw Socket Operations"
    echo -e ""
    echo -e "  ${CYAN}FOR FULL POWER:${NC}"
    echo -e "    Use Kali Linux / Parrot OS / Arch Linux"
    echo -e "    Or deploy via Docker on a VPS"
    echo -e ""
    echo -e "${YELLOW}============================================================${NC}"
}

print_summary() {
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${GREEN}  WOLFSTRIKE Termux Installation Complete!${NC}"
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
    echo -e "  Note: Restart Termux or run:"
    echo -e "    ${GREEN}source ~/.bashrc${NC}"
    echo ""
    echo -e "  ${BLUE}Wolf Intelligence PK | ATHEX BLACK HAT${NC}"
    echo ""
}

main() {
    echo -e "${BLUE}[*] Starting WOLFSTRIKE Termux installation...${NC}"
    echo ""
    
    check_termux
    install_termux_dependencies
    create_directories
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
    if [[ -f "$PROJECT_DIR/wolfstrike.py" ]]; then
        echo -e "${GREEN}[+] Installing from local directory${NC}"
        cp -r "$PROJECT_DIR"/* "$INSTALL_DIR/"
    else
        echo -e "${YELLOW}[!] Local files not found${NC}"
        echo -e "${YELLOW}[!] Please ensure WOLFSTRIKE files are in $INSTALL_DIR${NC}"
    fi
    
    install_python_dependencies
    create_launcher
    setup_bashrc
    print_warning
    print_summary
}

main "$@"