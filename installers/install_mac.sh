#!/bin/bash
# ============================================================
# WOLFSTRIKE macOS Installer
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

INSTALL_DIR="/usr/local/opt/wolfstrike"
CONFIG_DIR="$HOME/.config/wolfstrike"
DATA_DIR="$HOME/Library/Application Support/WolfStrike"

MIN_PYTHON_VERSION="3.10"

echo -e "${CYAN}"
echo "============================================================"
echo "  WOLFSTRIKE v1.0.0 - macOS Installer"
echo "  Wolf Intelligence PK | ATHEX BLACK HAT"
echo "============================================================"
echo -e "${NC}"

check_homebrew() {
    echo -e "${BLUE}[*] Checking Homebrew installation...${NC}"
    
    if command -v brew &> /dev/null; then
        echo -e "${GREEN}[+] Homebrew found${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Homebrew not found${NC}"
        echo -e "${YELLOW}[!] Homebrew is recommended for dependency management${NC}"
        echo -e "${YELLOW}[!] Install from: https://brew.sh${NC}"
        return 1
    fi
}

check_python() {
    echo -e "${BLUE}[*] Checking Python installation...${NC}"
    
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        echo -e "${GREEN}[+] Python $PYTHON_VERSION found${NC}"
        
        if [[ $(echo "$PYTHON_VERSION >= $MIN_PYTHON_VERSION" | bc -l 2>/dev/null || echo "1") -eq 1 ]]; then
            echo -e "${GREEN}[+] Python version meets minimum requirement${NC}"
            return 0
        else
            echo -e "${RED}[-] Python $MIN_PYTHON_VERSION or higher is required${NC}"
            return 1
        fi
    else
        echo -e "${RED}[-] Python3 not found${NC}"
        return 1
    fi
}

install_system_dependencies() {
    echo -e "${BLUE}[*] Installing system dependencies...${NC}"
    
    if command -v brew &> /dev/null; then
        brew install \
            nmap \
            whois \
            bind \
            tor \
            proxychains-ng \
            chromium \
            chromedriver \
            2>/dev/null || true
        echo -e "${GREEN}[+] System dependencies installed via Homebrew${NC}"
    else
        echo -e "${YELLOW}[!] Install Homebrew first for automatic dependency installation${NC}"
        echo -e "${YELLOW}[!] Required: nmap, whois, bind (dig), tor${NC}"
    fi
}

create_directories() {
    echo -e "${BLUE}[*] Creating directories...${NC}"
    
    sudo mkdir -p "$INSTALL_DIR" 2>/dev/null || mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$DATA_DIR/logs"
    mkdir -p "$DATA_DIR/reports"
    
    if [[ -d "$INSTALL_DIR" ]]; then
        sudo chown -R "$(whoami):admin" "$INSTALL_DIR" 2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] Directories created${NC}"
}

install_python_dependencies() {
    echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
    
    cd "$INSTALL_DIR"
    
    if [[ -f "requirements.txt" ]]; then
        pip3 install --upgrade pip setuptools wheel
        pip3 install -r requirements.txt
        echo -e "${GREEN}[+] Python dependencies installed${NC}"
    else
        echo -e "${RED}[-] requirements.txt not found${NC}"
        return 1
    fi
}

create_launcher() {
    echo -e "${BLUE}[*] Creating launcher...${NC}"
    
    LAUNCHER="/usr/local/bin/wolfstrike"
    
    sudo tee "$LAUNCHER" > /dev/null << 'EOF'
#!/bin/bash
cd /usr/local/opt/wolfstrike
python3 wolfstrike.py "$@"
EOF
    
    sudo chmod +x "$LAUNCHER"
    echo -e "${GREEN}[+] Launcher created: /usr/local/bin/wolfstrike${NC}"
}

setup_configuration() {
    echo -e "${BLUE}[*] Setting up configuration...${NC}"
    
    if [[ ! -f "$CONFIG_DIR/settings.yaml" ]]; then
        if [[ -f "$INSTALL_DIR/config/settings.yaml" ]]; then
            cp "$INSTALL_DIR/config/settings.yaml" "$CONFIG_DIR/settings.yaml"
            echo -e "${GREEN}[+] Configuration file created${NC}"
        fi
    fi
}

verify_installation() {
    echo -e "${BLUE}[*] Verifying installation...${NC}"
    
    ERRORS=0
    
    if [[ ! -f "$INSTALL_DIR/wolfstrike.py" ]]; then
        echo -e "${RED}[-] Main script not found${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    if ! python3 -c "import requests" 2>/dev/null; then
        echo -e "${YELLOW}[!] Python requests module not found${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    if [[ $ERRORS -eq 0 ]]; then
        echo -e "${GREEN}[+] Installation verified successfully${NC}"
        return 0
    else
        return 1
    fi
}

print_summary() {
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${GREEN}  WOLFSTRIKE macOS Installation Complete!${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
    echo -e "  Installation Directory: ${YELLOW}$INSTALL_DIR${NC}"
    echo -e "  Configuration:          ${YELLOW}$CONFIG_DIR${NC}"
    echo -e "  Data Directory:         ${YELLOW}$DATA_DIR${NC}"
    echo ""
    echo -e "  Quick Start:"
    echo -e "    ${GREEN}wolfstrike --target example.com${NC}"
    echo -e "    ${GREEN}wolfstrike --interactive${NC}"
    echo -e "    ${GREEN}wolfstrike --help${NC}"
    echo ""
    echo -e "  ${BLUE}Wolf Intelligence PK | ATHEX BLACK HAT${NC}"
    echo ""
}

main() {
    echo -e "${BLUE}[*] Starting WOLFSTRIKE macOS installation...${NC}"
    echo ""
    
    check_homebrew || true
    check_python || exit 1
    
    create_directories
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
    if [[ -f "$PROJECT_DIR/wolfstrike.py" ]]; then
        echo -e "${GREEN}[+] Installing from local directory${NC}"
        sudo cp -r "$PROJECT_DIR"/* "$INSTALL_DIR/" 2>/dev/null || cp -r "$PROJECT_DIR"/* "$INSTALL_DIR/"
        
        if [[ -d "$INSTALL_DIR" ]]; then
            sudo chown -R "$(whoami):admin" "$INSTALL_DIR" 2>/dev/null || true
        fi
    else
        echo -e "${YELLOW}[!] Local files not found${NC}"
    fi
    
    install_system_dependencies
    install_python_dependencies
    setup_configuration
    create_launcher
    
    if verify_installation; then
        print_summary
        exit 0
    else
        echo -e "${RED}[-] Installation completed with errors${NC}"
        exit 1
    fi
}

main "$@"