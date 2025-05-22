#!/bin/bash

# Enhanced Personal Bug Bounty Assistant Setup Script
# Version 2.0 - Complete Installation and Configuration

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
PYTHON_MIN_VERSION="3.8"
GO_MIN_VERSION="1.19"
TOOL_DIR="$HOME/.local/bin"
CONFIG_DIR="$HOME/.config/enhanced-bb-assistant"
LOG_FILE="/tmp/bb_assistant_setup.log"

# Banner
print_banner() {
    echo -e "${PURPLE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║    Enhanced Personal Bug Bounty Assistant v2.0              ║
║    AI-Powered Security Testing with Platform Integration     ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Logging function
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
    echo -e "$1"
}

# Progress indicator
progress() {
    echo -e "${BLUE}[INFO]${NC} $1"
    log "[INFO] $1"
}

# Success indicator
success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
    log "[SUCCESS] $1"
}

# Warning indicator
warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
    log "[WARNING] $1"
}

# Error indicator
error() {
    echo -e "${RED}[ERROR]${NC} $1"
    log "[ERROR] $1"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Version comparison
version_ge() {
    printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# System detection
detect_system() {
    progress "Detecting system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        SYSTEM="linux"
        if command_exists apt-get; then
            PACKAGE_MANAGER="apt"
        elif command_exists yum; then
            PACKAGE_MANAGER="yum"
        elif command_exists pacman; then
            PACKAGE_MANAGER="pacman"
        else
            warning "Unknown package manager. Manual installation may be required."
            PACKAGE_MANAGER="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        SYSTEM="macos"
        PACKAGE_MANAGER="brew"
        if ! command_exists brew; then
            error "Homebrew not found. Please install Homebrew first: https://brew.sh/"
            exit 1
        fi
    elif [[ "$OSTYPE" == "cygwin" ]] || [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        SYSTEM="windows"
        warning "Windows detected. Some tools may require WSL or manual installation."
        PACKAGE_MANAGER="manual"
    else
        warning "Unknown operating system: $OSTYPE"
        SYSTEM="unknown"
        PACKAGE_MANAGER="manual"
    fi
    
    success "System detected: $SYSTEM with $PACKAGE_MANAGER"
}

# Check prerequisites
check_prerequisites() {
    progress "Checking prerequisites..."
    
    # Check Python
    if command_exists python3; then
        PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
        if version_ge "$PYTHON_VERSION" "$PYTHON_MIN_VERSION"; then
            success "Python $PYTHON_VERSION found (>= $PYTHON_MIN_VERSION required)"
        else
            error "Python $PYTHON_VERSION found, but >= $PYTHON_MIN_VERSION required"
            exit 1
        fi
    else
        error "Python 3 not found. Please install Python 3.8 or higher."
        exit 1
    fi
    
    # Check pip
    if ! command_exists pip3; then
        error "pip3 not found. Please install pip for Python 3."
        exit 1
    fi
    
    # Check Git
    if ! command_exists git; then
        warning "Git not found. Some installation steps may fail."
    else
        success "Git found"
    fi
    
    # Check Go (for security tools)
    if command_exists go; then
        GO_VERSION=$(go version | cut -d' ' -f3 | sed 's/go//')
        if version_ge "$GO_VERSION" "$GO_MIN_VERSION"; then
            success "Go $GO_VERSION found (>= $GO_MIN_VERSION required)"
            HAS_GO=true
        else
            warning "Go $GO_VERSION found, but >= $GO_MIN_VERSION recommended for security tools"
            HAS_GO=false
        fi
    else
        warning "Go not found. Security tools installation will be limited."
        HAS_GO=false
    fi
}

# Install system dependencies
install_system_dependencies() {
    progress "Installing system dependencies..."
    
    case $PACKAGE_MANAGER in
        apt)
            sudo apt-get update
            sudo apt-get install -y \
                python3-dev \
                python3-pip \
                python3-venv \
                build-essential \
                libssl-dev \
                libffi-dev \
                libxml2-dev \
                libxslt1-dev \
                zlib1g-dev \
                libjpeg-dev \
                curl \
                wget \
                git \
                nmap \
                dnsutils \
                whois
            ;;
        yum)
            sudo yum update -y
            sudo yum install -y \
                python3-devel \
                python3-pip \
                gcc \
                openssl-devel \
                libffi-devel \
                libxml2-devel \
                libxslt-devel \
                zlib-devel \
                libjpeg-devel \
                curl \
                wget \
                git \
                nmap \
                bind-utils \
                whois
            ;;
        brew)
            brew update
            brew install \
                python@3.11 \
                openssl \
                libffi \
                curl \
                wget \
                git \
                nmap \
                dnsutils \
                whois
            ;;
        *)
            warning "Manual installation required for system dependencies"
            ;;
    esac
    
    success "System dependencies installed"
}

# Create virtual environment
setup_python_environment() {
    progress "Setting up Python virtual environment..."
    
    # Create project directory
    mkdir -p "$HOME/enhanced-bb-assistant"
    cd "$HOME/enhanced-bb-assistant"
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip setuptools wheel
    
    success "Python virtual environment created"
}

# Install Python packages
install_python_packages() {
    progress "Installing Python packages..."
    
    # Ensure we're in the virtual environment
    source "$HOME/enhanced-bb-assistant/venv/bin/activate"
    
    # Install packages from requirements
    cat > requirements.txt << 'EOF'
# Enhanced Bug Bounty Assistant - Complete Requirements
openai>=1.12.0
requests>=2.31.0
urllib3>=1.26.0
pyyaml>=6.0
pathlib2>=2.3.7
typing_extensions>=4.0.0
httpx>=0.24.0
aiohttp>=3.8.0
beautifulsoup4>=4.12.0
lxml>=4.9.0
dnspython>=2.3.0
python-nmap>=0.7.1
pandas>=2.0.0
numpy>=1.24.0
cryptography>=41.0.0
pycryptodome>=3.18.0
colorama>=0.4.6
rich>=13.0.0
click>=8.1.0
python-dotenv>=1.0.0
configparser>=5.3.0
loguru>=0.7.0
selenium>=4.15.0
webdriver-manager>=4.0.0
python-jose>=3.3.0
jwt>=1.3.1
openpyxl>=3.1.0
python-docx>=0.8.11
boto3>=1.28.0
google-cloud-storage>=2.10.0
azure-storage-blob>=12.17.0
pytest>=7.4.0
pytest-asyncio>=0.21.0
black>=23.0.0
flake8>=6.0.0
EOF
    
    pip install -r requirements.txt
    
    success "Python packages installed"
}

# Install Go-based security tools
install_go_tools() {
    if [[ "$HAS_GO" == true ]]; then
        progress "Installing Go-based security tools..."
        
        # Create tools directory
        mkdir -p "$TOOL_DIR"
        
        # Install tools
        go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
        go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
        go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
        go install -v github.com/ffuf/ffuf@latest
        go install -v github.com/projectdiscovery/katana/cmd/katana@latest
        go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
        go install -v github.com/hakluke/hakrawler@latest
        go install -v github.com/tomnomnom/gau/v2/cmd/gau@latest
        go install -v github.com/tomnomnom/waybackurls@latest
        go install -v github.com/lc/gau@latest
        
        # Move tools to local bin if needed
        if [[ -d "$HOME/go/bin" ]]; then
            cp "$HOME/go/bin/"* "$TOOL_DIR/" 2>/dev/null || true
        fi
        
        success "Go-based security tools installed"
    else
        warning "Skipping Go tools installation (Go not available)"
    fi
}

# Install additional security tools
install_additional_tools() {
    progress "Installing additional security tools..."
    
    case $PACKAGE_MANAGER in
        apt)
            # Try to install from package manager first
            sudo apt-get install -y \
                gobuster \
                dirb \
                nikto \
                whatweb \
                dnsrecon \
                theharvester \
                amass || warning "Some tools failed to install via apt"
            ;;
        brew)
            brew install \
                gobuster \
                amass \
                nikto || warning "Some tools failed to install via brew"
            ;;
        *)
            warning "Manual installation required for additional tools"
            ;;
    esac
    
    # Install wordlists
    mkdir -p "$HOME/.wordlists"
    cd "$HOME/.wordlists"
    
    # Download SecLists if not present
    if [[ ! -d "SecLists" ]]; then
        progress "Downloading SecLists wordlists..."
        git clone https://github.com/danielmiessler/SecLists.git || warning "Failed to download SecLists"
    fi
    
    success "Additional security tools installation completed"
}

# Setup configuration
setup_configuration() {
    progress "Setting up configuration..."
    
    # Create config directory
    mkdir -p "$CONFIG_DIR"
    
    # Copy configuration file
    cat > "$CONFIG_DIR/config.yaml" << 'EOF'
# Enhanced Personal Bug Bounty Assistant Configuration
# IMPORTANT: Review and customize this configuration before use

# API Configuration
openai:
  model: "gpt-4"
  temperature: 0.7
  max_tokens: 4000

# Platform Integration (configure via environment variables)
platforms:
  hackerone:
    enabled: false  # Set to true when credentials are configured
    auto_submit: false
  bugcrowd:
    enabled: false  # Set to true when credentials are configured
    auto_submit: false

# Safety Settings
scope_validation:
  enabled: true  # CRITICAL: Always keep enabled
  strict_mode: true

aggressive_testing:
  enabled: false  # Enable only when you understand the risks
  
# Tool Integration
tools:
  subfinder: true
  httpx: true
  nuclei: true
  ffuf: true
  amass: true

# Rate Limiting (be respectful)
rate_limiting:
  enabled: true
  base_delay: 1.0
  max_concurrent_requests: 3

# Security
security:
  blocked_domains:
    - "localhost"
    - "127.0.0.1"
    - "internal"
    - "corp"
    - "local"
  max_auto_exploit_severity: "medium"
EOF
    
    # Create environment template
    cat > "$CONFIG_DIR/.env.template" << 'EOF'
# Enhanced Bug Bounty Assistant Environment Variables
# Copy this file to .env and fill in your actual values

# OpenAI API Key (Required)
OPENAI_API_KEY=your_openai_api_key_here

# HackerOne Credentials (Optional)
HACKERONE_USERNAME=your_hackerone_username
HACKERONE_API_TOKEN=your_hackerone_api_token

# Bugcrowd Credentials (Optional)
BUGCROWD_API_TOKEN=your_bugcrowd_api_token

# Burp Suite API (Optional)
BURP_API_KEY=your_burp_api_key

# Notification Settings (Optional)
SLACK_WEBHOOK_URL=your_slack_webhook_url
DISCORD_WEBHOOK_URL=your_discord_webhook_url

# Email Settings (Optional)
EMAIL_PASSWORD=your_email_password

# Proxy Settings (Optional)
HTTP_PROXY=http://proxy:8080
HTTPS_PROXY=https://proxy:8080
EOF
    
    success "Configuration files created in $CONFIG_DIR"
}

# Create launcher script
create_launcher() {
    progress "Creating launcher script..."
    
    cat > "$HOME/enhanced-bb-assistant/run_bb_assistant.sh" << 'EOF'
#!/bin/bash

# Enhanced Bug Bounty Assistant Launcher
cd "$(dirname "$0")"

# Activate virtual environment
source venv/bin/activate

# Check for required environment variables
if [[ -z "$OPENAI_API_KEY" ]]; then
    echo "❌ OPENAI_API_KEY not set. Please configure your environment variables."
    echo "📋 Copy $HOME/.config/enhanced-bb-assistant/.env.template to .env and fill in your values"
    exit 1
fi

# Add tools to PATH
export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"

# Run the assistant
python3 enhanced_personal_assistant.py "$@"
EOF
    
    chmod +x "$HOME/enhanced-bb-assistant/run_bb_assistant.sh"
    
    # Create symlink in user bin
    mkdir -p "$HOME/.local/bin"
    ln -sf "$HOME/enhanced-bb-assistant/run_bb_assistant.sh" "$HOME/.local/bin/bb-assistant"
    
    success "Launcher script created"
}

# Run tests
run_tests() {
    progress "Running installation tests..."
    
    cd "$HOME/enhanced-bb-assistant"
    source venv/bin/activate
    
    # Test Python imports
    python3 -c "
import openai
import requests
import yaml
import dns.resolver
import numpy as np
import pandas as pd
print('✅ All Python packages imported successfully')
" || error "Python package test failed"
    
    # Test Go tools
    export PATH="$HOME/.local/bin:$HOME/go/bin:$PATH"
    
    if command_exists subfinder; then
        success "✅ subfinder available"
    else
        warning "⚠️ subfinder not found"
    fi
    
    if command_exists httpx; then
        success "✅ httpx available"
    else
        warning "⚠️ httpx not found"
    fi
    
    if command_exists nuclei; then
        success "✅ nuclei available"
    else
        warning "⚠️ nuclei not found"
    fi
    
    success "Installation tests completed"
}

# Post-installation instructions
show_instructions() {
    echo -e "\n${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}║                    Installation Complete!                    ║${NC}"
    echo -e "${GREEN}║                                                              ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}\n"
    
    echo -e "${CYAN}📋 Next Steps:${NC}\n"
    
    echo -e "${WHITE}1. Configure API Keys:${NC}"
    echo -e "   ${YELLOW}cp $CONFIG_DIR/.env.template $CONFIG_DIR/.env${NC}"
    echo -e "   ${YELLOW}nano $CONFIG_DIR/.env${NC}"
    echo -e "   ${BLUE}# Add your OpenAI API key and platform credentials${NC}\n"
    
    echo -e "${WHITE}2. Review Configuration:${NC}"
    echo -e "   ${YELLOW}nano $CONFIG_DIR/config.yaml${NC}"
    echo -e "   ${BLUE}# Customize settings for your use case${NC}\n"
    
    echo -e "${WHITE}3. Test Installation:${NC}"
    echo -e "   ${YELLOW}bb-assistant --help${NC}"
    echo -e "   ${BLUE}# Should show help message${NC}\n"
    
    echo -e "${WHITE}4. Run Your First Hunt:${NC}"
    echo -e "   ${YELLOW}bb-assistant example.com --platform hackerone --program example${NC}"
    echo -e "   ${BLUE}# Replace with actual target and program${NC}\n"
    
    echo -e "${WHITE}5. Advanced Usage:${NC}"
    echo -e "   ${YELLOW}bb-assistant target.com --aggressive --config $CONFIG_DIR/config.yaml${NC}"
    echo -e "   ${BLUE}# Enable aggressive testing (use with caution)${NC}\n"
    
    echo -e "${RED}⚠️ Important Security Notes:${NC}"
    echo -e "${RED}   • Only test targets you have permission to test${NC}"
    echo -e "${RED}   • Review scope validation settings before testing${NC}"
    echo -e "${RED}   • Aggressive mode should only be used on authorized targets${NC}"
    echo -e "${RED}   • Always follow responsible disclosure practices${NC}\n"
    
    echo -e "${CYAN}📖 Documentation:${NC}"
    echo -e "   ${BLUE}• Configuration: $CONFIG_DIR/config.yaml${NC}"
    echo -e "   ${BLUE}• Environment: $CONFIG_DIR/.env${NC}"
    echo -e "   ${BLUE}• Logs: $LOG_FILE${NC}"
    echo -e "   ${BLUE}• Installation: $HOME/enhanced-bb-assistant/${NC}\n"
    
    echo -e "${CYAN}🛠️ Troubleshooting:${NC}"
    echo -e "   ${BLUE}• Check logs: tail -f $LOG_FILE${NC}"
    echo -e "   ${BLUE}• Update tools: bb-assistant --update-tools${NC}"
    echo -e "   ${BLUE}• Reinstall: rm -rf $HOME/enhanced-bb-assistant && ./setup.sh${NC}\n"
    
    echo -e "${GREEN}Happy Bug Hunting! 🎯${NC}\n"
}

# Main installation function
main() {
    print_banner
    
    progress "Starting Enhanced Bug Bounty Assistant installation..."
    log "Installation started at $(date)"
    
    detect_system
    check_prerequisites
    install_system_dependencies
    setup_python_environment
    install_python_packages
    install_go_tools
    install_additional_tools
    setup_configuration
    create_launcher
    run_tests
    
    success "Installation completed successfully!"
    log "Installation completed at $(date)"
    
    show_instructions
}

# Handle interrupts
trap 'error "Installation interrupted"; exit 1' INT TERM

# Run main function
main "$@"