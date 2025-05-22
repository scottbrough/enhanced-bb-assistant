#!/bin/bash

# Quick Fix Script for Go Tools Installation
# Addresses the immediate gau installation error

set -e

echo "🔧 Quick Fix: Installing Go-based security tools with correct paths..."

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Set Go environment for better reliability
export GOPROXY=https://proxy.golang.org,direct
export GOSUMDB=sum.golang.org
export GOPRIVATE=""

# Function to install a single tool safely
install_tool() {
    local tool_path="$1"
    local tool_name="$2"
    
    echo -e "${YELLOW}Installing $tool_name...${NC}"
    
    if timeout 300 go install -v "$tool_path@latest"; then
        echo -e "${GREEN}✅ $tool_name installed successfully${NC}"
        return 0
    else
        echo -e "${RED}❌ $tool_name installation failed${NC}"
        return 1
    fi
}

echo "📦 Installing security tools with corrected paths..."

# CORRECTED TOOL PATHS (this fixes your error)
install_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"
install_tool "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"
install_tool "github.com/projectdiscovery/nuclei/v2/cmd/nuclei" "nuclei"
install_tool "github.com/ffuf/ffuf/v2" "ffuf"
install_tool "github.com/lc/gau/v2/cmd/gau" "gau"  # CORRECTED: lc not tomnomnom
install_tool "github.com/tomnomnom/waybackurls" "waybackurls"
install_tool "github.com/projectdiscovery/katana/cmd/katana" "katana"
install_tool "github.com/hakluke/hakrawler" "hakrawler"
install_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu" "naabu"

echo ""
echo -e "${GREEN}🎉 Tools installation completed!${NC}"
echo ""
echo "🔍 Checking installed tools:"

# Check which tools are now available
tools=("subfinder" "httpx" "nuclei" "ffuf" "gau" "waybackurls" "katana" "hakrawler" "naabu")

for tool in "${tools[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}✅ $tool${NC} - $(which $tool)"
    else
        echo -e "${RED}❌ $tool${NC} - not found in PATH"
    fi
done

echo ""
echo "💡 Tips:"
echo "• Add $HOME/go/bin to your PATH if tools aren't found"
echo "• Run: export PATH=\$PATH:\$HOME/go/bin"
echo "• Add that line to your ~/.bashrc or ~/.zshrc for permanent access"
echo ""
echo -e "${GREEN}✅ Quick fix completed!${NC}"