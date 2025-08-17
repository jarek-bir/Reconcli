#!/bin/bash

# 🔍 VHostCLI Dependencies Quick Checker
# ReconCLI Virtual Host Discovery Tool Status Check
# Author: jarek-bir

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Emojis
CHECKMARK="✅"
CROSS="❌"
WARNING="⚠️"
INFO="ℹ️"

print_header() {
    echo -e "${BLUE}🔍 VHostCLI Dependencies Status Check${NC}"
    echo "════════════════════════════════════════════════════════════════"
}

check_tool() {
    local tool="$1"
    local description="$2"
    local install_cmd="$3"
    
    if command -v "$tool" >/dev/null 2>&1; then
        if [[ "$tool" == "VhostFinder" ]]; then
            echo -e "${GREEN}${CHECKMARK} $description${NC}"
        else
            local version=$($tool --version 2>/dev/null | head -n1 || echo "unknown")
            echo -e "${GREEN}${CHECKMARK} $description ($version)${NC}"
        fi
        return 0
    else
        echo -e "${RED}${CROSS} $description - NOT FOUND${NC}"
        if [[ -n "$install_cmd" ]]; then
            echo -e "${YELLOW}   ${INFO} Install with: $install_cmd${NC}"
        fi
        return 1
    fi
}

check_python_package() {
    local package="$1"
    local description="$2"
    
    if python3 -c "import $package" 2>/dev/null || python -c "import $package" 2>/dev/null; then
        echo -e "${GREEN}${CHECKMARK} $description${NC}"
        return 0
    else
        echo -e "${RED}${CROSS} $description - NOT FOUND${NC}"
        echo -e "${YELLOW}   ${INFO} Install with: pip install $package${NC}"
        return 1
    fi
}

check_vhostfinder() {
    if [ -f "/usr/local/bin/VhostFinder" ]; then
        echo -e "${GREEN}${CHECKMARK} VhostFinder (installed at /usr/local/bin/)${NC}"
        return 0
    else
        echo -e "${RED}${CROSS} VhostFinder - NOT FOUND${NC}"
        echo -e "${YELLOW}   ${INFO} Install from: https://github.com/wdahlenburg/VhostFinder${NC}"
        return 1
    fi
}

main() {
    print_header
    
    echo -e "\n${YELLOW}Core Virtual Host Discovery Engines:${NC}"
    echo "──────────────────────────────────────"
    missing_core=0
    check_tool "ffuf" "FFUF (Fast web fuzzer)" "go install github.com/ffuf/ffuf/v2@latest" || ((missing_core++))
    check_tool "gobuster" "Gobuster (Directory/vhost bruteforcer)" "go install github.com/OJ/gobuster/v3@latest" || ((missing_core++))
    check_python_package "httpx" "HTTPx (Python HTTP toolkit)" || ((missing_core++))
    check_vhostfinder || ((missing_core++))
    
    echo -e "\n${YELLOW}Screenshot Tools:${NC}"
    echo "─────────────────"
    missing_screenshot=0
    check_tool "gowitness" "Gowitness (Web screenshotter)" "go install github.com/sensepost/gowitness@latest" || ((missing_screenshot++))
    check_tool "aquatone" "Aquatone (Alternative screenshotter)" "go install github.com/michenriksen/aquatone@latest" || ((missing_screenshot++))
    
    echo -e "\n${YELLOW}Port Scanners (for discovery):${NC}"
    echo "──────────────────────────────"
    missing_scanners=0
    check_tool "naabu" "Naabu (Fast port scanner)" "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" || ((missing_scanners++))
    check_tool "jfscan" "JFScan (Advanced masscan wrapper)" "pip install jfscan" || ((missing_scanners++))
    check_tool "nmap" "Nmap (Network mapper)" "apt install nmap / yum install nmap" || ((missing_scanners++))
    check_tool "masscan" "Masscan (Fast port scanner)" "apt install masscan / yum install masscan" || ((missing_scanners++))
    
    echo -e "\n${YELLOW}Vulnerability Scanner:${NC}"
    echo "─────────────────────────"
    missing_vuln=0
    check_tool "nuclei" "Nuclei (Vulnerability scanner)" "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" || ((missing_vuln++))
    
    echo -e "\n${YELLOW}Optional Dependencies:${NC}"
    echo "──────────────────────"
    missing_optional=0
    check_python_package "openai" "OpenAI (AI analysis)" || ((missing_optional++))
    check_python_package "sqlalchemy" "SQLAlchemy (Database storage)" || ((missing_optional++))
    check_python_package "click" "Click (CLI framework)" || ((missing_optional++))
    check_python_package "requests" "Requests (HTTP library)" || ((missing_optional++))
    
    echo -e "\n${YELLOW}Prerequisites:${NC}"
    echo "──────────────"
    missing_prereq=0
    check_tool "go" "Go language" "https://golang.org/dl/" || ((missing_prereq++))
    check_tool "git" "Git version control" "apt install git / yum install git" || ((missing_prereq++))
    if command -v pip3 >/dev/null 2>&1 || command -v pip >/dev/null 2>&1; then
        echo -e "${GREEN}${CHECKMARK} Python/pip${NC}"
    else
        echo -e "${RED}${CROSS} Python/pip - NOT FOUND${NC}"
        ((missing_prereq++))
    fi
    
    # Summary
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}SUMMARY:${NC}"
    
    total_missing=$((missing_core + missing_screenshot + missing_scanners + missing_vuln + missing_optional + missing_prereq))
    
    if [[ $missing_prereq -gt 0 ]]; then
        echo -e "${RED}${CROSS} Prerequisites missing: $missing_prereq${NC}"
        echo -e "${YELLOW}   ${WARNING} Install prerequisites first before running VHostCLI installer${NC}"
    fi
    
    if [[ $missing_core -gt 0 ]]; then
        echo -e "${RED}${CROSS} Core engines missing: $missing_core${NC}"
        echo -e "${YELLOW}   ${WARNING} VHostCLI requires at least one core engine${NC}"
    else
        echo -e "${GREEN}${CHECKMARK} All core engines available${NC}"
    fi
    
    if [[ $missing_scanners -gt 0 ]]; then
        echo -e "${YELLOW}${WARNING} Port scanners missing: $missing_scanners (optional for enhanced discovery)${NC}"
    else
        echo -e "${GREEN}${CHECKMARK} All port scanners available${NC}"
    fi
    
    if [[ $missing_vuln -gt 0 ]]; then
        echo -e "${YELLOW}${WARNING} Vulnerability scanner missing: $missing_vuln (optional for security assessment)${NC}"
    else
        echo -e "${GREEN}${CHECKMARK} Vulnerability scanner available${NC}"
    fi
    
    if [[ $missing_screenshot -gt 0 ]]; then
        echo -e "${YELLOW}${WARNING} Screenshot tools missing: $missing_screenshot (optional)${NC}"
    else
        echo -e "${GREEN}${CHECKMARK} All screenshot tools available${NC}"
    fi
    
    if [[ $missing_optional -gt 0 ]]; then
        echo -e "${YELLOW}${INFO} Optional dependencies missing: $missing_optional${NC}"
    else
        echo -e "${GREEN}${CHECKMARK} All optional dependencies available${NC}"
    fi
    
    if [[ $total_missing -eq 0 ]]; then
        echo -e "\n${GREEN}🎉 ALL DEPENDENCIES SATISFIED! VHostCLI is ready to use! 🎉${NC}"
    else
        echo -e "\n${YELLOW}${INFO} Run './install_vhostcli_deps.sh' to install missing dependencies${NC}"
    fi
    
    # Check wordlist
    echo -e "\n${YELLOW}Wordlists:${NC}"
    echo "──────────"
    if [ -f "$HOME/.reconcli/wordlists/vhost_common.txt" ]; then
        lines=$(wc -l < "$HOME/.reconcli/wordlists/vhost_common.txt")
        echo -e "${GREEN}${CHECKMARK} Example wordlist available ($lines entries)${NC}"
    else
        echo -e "${YELLOW}${INFO} Example wordlist not found${NC}"
        echo -e "${YELLOW}   ${INFO} Will be created by installer${NC}"
    fi
}

main "$@"
