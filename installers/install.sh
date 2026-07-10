#!/bin/bash
# ============================================================
# WOLFSTRIKE Linux Installer
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

INSTALL_DIR="/opt/wolfstrike"
CONFIG_DIR="$HOME/.config/wolfstrike"
DATA_DIR="$HOME/.local/share/wolfstrike"
LOG_DIR="$DATA_DIR/logs"
REPORT_DIR="$DATA_DIR/reports"

MIN_PYTHON_VERSION="3.10"

echo -e "${CYAN}"
echo "============================================================"
echo "  WOLFSTRIKE v1.0.0 - Linux Installer"
echo "  Wolf Intelligence PK | ATHEX BLACK HAT"
echo "============================================================"
echo -e "${NC}"

check_root() {
    if [[ $EUID -eq 0 ]]; then
        echo -e "${GREEN}[+] Running with root privileges${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] Running without root privileges${NC}"
        echo -e "${YELLOW}[!] Some features may be limited${NC}"
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

check_pip() {
    echo -e "${BLUE}[*] Checking pip installation...${NC}"
    
    if command -v pip3 &> /dev/null; then
        echo -e "${GREEN}[+] pip3 found${NC}"
        return 0
    else
        echo -e "${YELLOW}[!] pip3 not found, attempting to install...${NC}"
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            sudo yum install -y python3-pip
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y python3-pip
        elif command -v pacman &> /dev/null; then
            sudo pacman -S --noconfirm python-pip
        else
            echo -e "${RED}[-] Could not install pip. Please install manually.${NC}"
            return 1
        fi
        return 0
    fi
}

check_git() {
    echo -e "${BLUE}[*] Checking git installation...${NC}"
    
    if command -v git &> /dev/null; then
        echo -e "${GREEN}[+] git found${NC}"
        return 0
    else
        echo -e "${RED}[-] git is required for installation${NC}"
        echo -e "${YELLOW}[!] Install git: sudo apt-get install git${NC}"
        return 1
    fi
}

install_system_dependencies() {
    echo -e "${BLUE}[*] Installing system dependencies...${NC}"
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq \
            python3-dev \
            python3-venv \
            build-essential \
            libssl-dev \
            libffi-dev \
            libxml2-dev \
            libxslt1-dev \
            zlib1g-dev \
            libjpeg-dev \
            libpng-dev \
            nmap \
            whois \
            dnsutils \
            tor \
            proxychains4 \
            chromium-browser \
            chromium-chromedriver \
            2>/dev/null || true
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm --needed \
            python \
            python-pip \
            python-setuptools \
            base-devel \
            openssl \
            libffi \
            libxml2 \
            libxslt \
            nmap \
            whois \
            bind-tools \
            tor \
            proxychains-ng \
            chromium \
            2>/dev/null || true
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y \
            python3-devel \
            gcc \
            openssl-devel \
            libffi-devel \
            libxml2-devel \
            libxslt-devel \
            nmap \
            whois \
            bind-utils \
            tor \
            proxychains-ng \
            chromium \
            2>/dev/null || true
    fi
    
    echo -e "${GREEN}[+] System dependencies installed${NC}"
}

create_directories() {
    echo -e "${BLUE}[*] Creating directories...${NC}"
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$REPORT_DIR"
    
    echo -e "${GREEN}[+] Directories created${NC}"
}

install_python_dependencies() {
    echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
    
    cd "$INSTALL_DIR"
    
    if [[ -f "requirements.txt" ]]; then
        pip3 install --upgrade pip
        pip3 install -r requirements.txt
        echo -e "${GREEN}[+] Python dependencies installed${NC}"
    else
        echo -e "${RED}[-] requirements.txt not found${NC}"
        return 1
    fi
}

setup_configuration() {
    echo -e "${BLUE}[*] Setting up configuration...${NC}"
    
    if [[ ! -f "$CONFIG_DIR/settings.yaml" ]]; then
        if [[ -f "$INSTALL_DIR/config/settings.yaml" ]]; then
            cp "$INSTALL_DIR/config/settings.yaml" "$CONFIG_DIR/settings.yaml"
            echo -e "${GREEN}[+] Configuration file created${NC}"
        fi
    else
        echo -e "${YELLOW}[!] Configuration file already exists, skipping${NC}"
    fi
    
    if [[ ! -f "$CONFIG_DIR/.env" ]]; then
        touch "$CONFIG_DIR/.env"
        echo -e "${GREEN}[+] Environment file created${NC}"
    fi
}

create_launcher() {
    echo -e "${BLUE}[*] Creating launcher script...${NC}"
    
    LAUNCHER="/usr/local/bin/wolfstrike"
    
    sudo tee "$LAUNCHER" > /dev/null << 'EOF'
#!/bin/bash
cd /opt/wolfstrike
python3 wolfstrike.py "$@"
EOF
    
    sudo chmod +x "$LAUNCHER"
    echo -e "${GREEN}[+] Launcher created: /usr/local/bin/wolfstrike${NC}"
}

setup_bash_completion() {
    echo -e "${BLUE}[*] Setting up bash completion...${NC}"
    
    COMPLETION_DIR="/etc/bash_completion.d"
    
    if [[ -d "$COMPLETION_DIR" ]]; then
        sudo tee "$COMPLETION_DIR/wolfstrike" > /dev/null << 'EOF'
_wolfstrike_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    opts="--target --file --quick --full-power --interactive --module --stealth --tor --proxy --threads --timeout --delay --output --report --verbose --debug --quiet --help --version --banner"
    
    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
        return 0
    fi
}

complete -F _wolfstrike_completion wolfstrike
EOF
        echo -e "${GREEN}[+] Bash completion installed${NC}"
    fi
}

install_docker_support() {
    if command -v docker &> /dev/null; then
        echo -e "${BLUE}[*] Docker detected, building container...${NC}"
        
        if [[ -f "$INSTALL_DIR/Dockerfile" ]]; then
            docker build -t wolfstrike:latest "$INSTALL_DIR" 2>/dev/null || true
            echo -e "${GREEN}[+] Docker image built${NC}"
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
    
    if ! python3 -c "import yaml" 2>/dev/null; then
        echo -e "${YELLOW}[!] Python yaml module not found${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    if ! python3 -c "import rich" 2>/dev/null; then
        echo -e "${YELLOW}[!] Python rich module not found${NC}"
        ERRORS=$((ERRORS + 1))
    fi
    
    if [[ $ERRORS -eq 0 ]]; then
        echo -e "${GREEN}[+] Installation verified successfully${NC}"
        return 0
    else
        echo -e "${RED}[-] Installation verification failed with $ERRORS errors${NC}"
        return 1
    fi
}

print_summary() {
    echo ""
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${GREEN}  WOLFSTRIKE Installation Complete!${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
    echo -e "  Installation Directory: ${YELLOW}$INSTALL_DIR${NC}"
    echo -e "  Configuration:          ${YELLOW}$CONFIG_DIR${NC}"
    echo -e "  Logs:                   ${YELLOW}$LOG_DIR${NC}"
    echo -e "  Reports:                ${YELLOW}$REPORT_DIR${NC}"
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
    echo -e "${BLUE}[*] Starting WOLFSTRIKE installation...${NC}"
    echo ""
    
    check_root || true
    check_python || exit 1
    check_pip || exit 1
    check_git || exit 1
    
    create_directories
    
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
    
    if [[ -f "$PROJECT_DIR/wolfstrike.py" ]]; then
        echo -e "${GREEN}[+] Installing from local directory${NC}"
        cp -r "$PROJECT_DIR"/* "$INSTALL_DIR/"
    else
        echo -e "${YELLOW}[!] Local files not found, skipping copy${NC}"
        echo -e "${YELLOW}[!] Please ensure WOLFSTRIKE files are in $INSTALL_DIR${NC}"
    fi
    
    install_system_dependencies
    install_python_dependencies
    setup_configuration
    create_launcher
    setup_bash_completion
    install_docker_support
    
    if verify_installation; then
        print_summary
        exit 0
    else
        echo -e "${RED}[-] Installation completed with errors${NC}"
        exit 1
    fi
}

main "$@"