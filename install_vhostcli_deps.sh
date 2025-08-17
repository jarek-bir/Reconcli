#!/bin/bash

# 🎯 VHostCLI Universal Dependencies Installer
# ReconCLI Virtual Host Discovery Tool Setup
# Author: jarek-bir
# Date: July 2025

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Emojis for better UX
CHECKMARK="✅"
CROSS="❌"
ARROW="🔧"
GEAR="⚙️"
ROCKET="🚀"
TARGET="🎯"
CAMERA="📸"
BRAIN="🧠"
DATABASE="💾"

print_header() {
    echo -e "${BLUE}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${TARGET} VHostCLI Universal Dependencies Installer ${TARGET}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${CYAN}${GEAR} $1${NC}"
    echo "────────────────────────────────────────────────────────────────────────────"
}

check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        echo -e "${GREEN}${CHECKMARK} $1 is already installed${NC}"
        return 0
    else
        echo -e "${YELLOW}${ARROW} $1 not found, installing...${NC}"
        return 1
    fi
}

install_go_tool() {
    local tool_url="$1"
    local tool_name="$2"
    
    echo -e "${BLUE}${ROCKET} Installing $tool_name...${NC}"
    if go install "$tool_url"; then
        echo -e "${GREEN}${CHECKMARK} $tool_name installed successfully${NC}"
    else
        echo -e "${RED}${CROSS} Failed to install $tool_name${NC}"
        return 1
    fi
}

install_python_package() {
    local package="$1"
    
    echo -e "${BLUE}${ROCKET} Installing Python package: $package...${NC}"
    if pip install "$package"; then
        echo -e "${GREEN}${CHECKMARK} $package installed successfully${NC}"
    else
        echo -e "${RED}${CROSS} Failed to install $package${NC}"
        return 1
    fi
}

check_prerequisites() {
    print_section "Checking Prerequisites"
    
    # Check if Go is installed
    if ! command -v go >/dev/null 2>&1; then
        echo -e "${RED}${CROSS} Go is not installed. Please install Go first:${NC}"
        echo "  • Ubuntu/Debian: sudo apt install golang-go"
        echo "  • CentOS/RHEL: sudo yum install golang"
        echo "  • macOS: brew install go"
        echo "  • Or download from: https://golang.org/dl/"
        exit 1
    else
        echo -e "${GREEN}${CHECKMARK} Go is installed ($(go version))${NC}"
    fi
    
    # Check if Python/pip is installed
    if ! command -v pip >/dev/null 2>&1 && ! command -v pip3 >/dev/null 2>&1; then
        echo -e "${RED}${CROSS} pip is not installed. Please install Python and pip first${NC}"
        exit 1
    else
        if command -v pip3 >/dev/null 2>&1; then
            PIP_CMD="pip3"
        else
            PIP_CMD="pip"
        fi
        echo -e "${GREEN}${CHECKMARK} Python/pip is installed${NC}"
    fi
    
    # Check if git is installed (needed for VhostFinder)
    if ! command -v git >/dev/null 2>&1; then
        echo -e "${RED}${CROSS} git is not installed. Please install git first${NC}"
        exit 1
    else
        echo -e "${GREEN}${CHECKMARK} git is installed${NC}"
    fi
}

install_core_engines() {
    print_section "Installing Core Virtual Host Discovery Engines"
    
    # FFUF - Fast web fuzzer (default engine)
    if ! check_command "ffuf"; then
        install_go_tool "github.com/ffuf/ffuf/v2@latest" "FFUF"
    fi
    
    # Gobuster - Directory/DNS/vhost bruteforcer
    if ! check_command "gobuster"; then
        install_go_tool "github.com/OJ/gobuster/v3@latest" "Gobuster"
    fi
    
    # HTTPx - HTTP toolkit (Python version for VHostCLI)
    echo -e "${BLUE}${ROCKET} Installing HTTPx (Python)...${NC}"
    $PIP_CMD install httpx
    echo -e "${GREEN}${CHECKMARK} HTTPx (Python) installed${NC}"
    
    # Nuclei - Vulnerability scanner
    if ! check_command "nuclei"; then
        install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" "Nuclei"
    fi
}

install_vhostfinder() {
    print_section "Installing VhostFinder (Specialized Engine)"
    
    if [ -f "/usr/local/bin/VhostFinder" ]; then
        echo -e "${GREEN}${CHECKMARK} VhostFinder is already installed${NC}"
        return 0
    fi
    
    echo -e "${BLUE}${ROCKET} Installing VhostFinder from source...${NC}"
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Clone and build VhostFinder
    if git clone https://github.com/wdahlenburg/VhostFinder.git; then
        cd VhostFinder
        if go build -o VhostFinder; then
            # Install to system path
            if sudo cp VhostFinder /usr/local/bin/; then
                sudo chmod +x /usr/local/bin/VhostFinder
                echo -e "${GREEN}${CHECKMARK} VhostFinder installed to /usr/local/bin/${NC}"
            else
                echo -e "${YELLOW}${ARROW} Could not install to /usr/local/bin/ (permission denied)${NC}"
                echo -e "${YELLOW}${ARROW} You can manually copy VhostFinder to your PATH${NC}"
                echo -e "Current location: $TEMP_DIR/VhostFinder/VhostFinder"
            fi
        else
            echo -e "${RED}${CROSS} Failed to build VhostFinder${NC}"
        fi
    else
        echo -e "${RED}${CROSS} Failed to clone VhostFinder repository${NC}"
    fi
    
    # Cleanup
    cd /
    rm -rf "$TEMP_DIR"
}

install_screenshot_tools() {
    print_section "Installing Screenshot Tools"
    
    # Gowitness - Web screenshotter (default)
    if ! check_command "gowitness"; then
        install_go_tool "github.com/sensepost/gowitness@latest" "Gowitness"
    fi
    
    # Aquatone - Alternative screenshotter
    if ! check_command "aquatone"; then
        install_go_tool "github.com/michenriksen/aquatone@latest" "Aquatone"
    fi
}

install_port_scanners() {
    print_section "Installing Port Scanners for Discovery"
    
    # Naabu - Fast port scanner
    if ! check_command "naabu"; then
        install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" "Naabu"
    fi
    
    # JFScan - Advanced masscan + nmap wrapper
    if ! check_command "jfscan"; then
        echo -e "${BLUE}${ROCKET} Installing JFScan (Just Fu*king Scan)...${NC}"
        $PIP_CMD install jfscan
        echo -e "${GREEN}${CHECKMARK} JFScan installed successfully${NC}"
    fi
    
    # Check if nmap is available (system package)
    if ! check_command "nmap"; then
        echo -e "${YELLOW}${ARROW} nmap not found. Install with:${NC}"
        echo "  • Ubuntu/Debian: sudo apt install nmap"
        echo "  • CentOS/RHEL: sudo yum install nmap"
        echo "  • macOS: brew install nmap"
    fi
    
    # Check if masscan is available (system package)
    if ! check_command "masscan"; then
        echo -e "${YELLOW}${ARROW} masscan not found. Install with:${NC}"
        echo "  • Ubuntu/Debian: sudo apt install masscan"
        echo "  • CentOS/RHEL: sudo yum install masscan"
        echo "  • macOS: brew install masscan"
    fi
}
    print_section "Installing Optional Dependencies"
    
    # AI Analysis dependencies
    echo -e "${BRAIN} Installing AI analysis dependencies..."
    $PIP_CMD install openai
    echo -e "${GREEN}${CHECKMARK} OpenAI package installed${NC}"
    
    # Database storage dependencies
    echo -e "${DATABASE} Installing database dependencies..."
    $PIP_CMD install "sqlalchemy>=2.0.0"
    echo -e "${GREEN}${CHECKMARK} SQLAlchemy installed${NC}"
    
    # Additional useful packages
    echo -e "${BLUE}${ROCKET} Installing additional Python packages...${NC}"
    $PIP_CMD install click requests rich
    echo -e "${GREEN}${CHECKMARK} Additional packages installed${NC}"
}

verify_installation() {
    print_section "Verifying Installation"
    
    echo -e "${YELLOW}Checking installed tools:${NC}"
    
    # Core engines
    tools=("ffuf" "gobuster" "nuclei")
    for tool in "${tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            version=$($tool --version 2>/dev/null | head -n1 || echo "unknown")
            echo -e "${GREEN}${CHECKMARK} $tool: $version${NC}"
        else
            echo -e "${RED}${CROSS} $tool: not found${NC}"
        fi
    done
    
    # VhostFinder (special case)
    if [ -f "/usr/local/bin/VhostFinder" ]; then
        echo -e "${GREEN}${CHECKMARK} VhostFinder: installed at /usr/local/bin/${NC}"
    else
        echo -e "${RED}${CROSS} VhostFinder: not found${NC}"
    fi
    
    # Screenshot tools
    screenshot_tools=("gowitness" "aquatone")
    for tool in "${screenshot_tools[@]}"; do
        if command -v "$tool" >/dev/null 2>&1; then
            echo -e "${GREEN}${CHECKMARK} $tool: installed${NC}"
        else
            echo -e "${RED}${CROSS} $tool: not found${NC}"
        fi
    done
    
    # Port scanners
    scanners=("naabu" "nmap" "masscan" "jfscan")
    for scanner in "${scanners[@]}"; do
        if command -v "$scanner" &> /dev/null; then
            echo -e "  ${GREEN}✓${NC} $scanner is available"
        else
            echo -e "  ${RED}✗${NC} $scanner is not available"
        fi
    done
    echo -e "\n${YELLOW}Checking Python packages:${NC}"
    python_packages=("httpx" "openai" "sqlalchemy" "click" "requests" "rich")
    for package in "${python_packages[@]}"; do
        if python -c "import $package" 2>/dev/null || python3 -c "import $package" 2>/dev/null; then
            echo -e "${GREEN}${CHECKMARK} $package: installed${NC}"
        else
            echo -e "${RED}${CROSS} $package: not found${NC}"
        fi
    done
}

create_wordlist_example() {
    print_section "Creating Example Wordlist"
    
    WORDLIST_DIR="$HOME/.reconcli/wordlists"
    mkdir -p "$WORDLIST_DIR"
    
    VHOST_WORDLIST="$WORDLIST_DIR/vhost_common.txt"
    
    if [ ! -f "$VHOST_WORDLIST" ]; then
        echo -e "${BLUE}${ROCKET} Creating example vhost wordlist...${NC}"
        cat > "$VHOST_WORDLIST" << 'EOF'
admin
api
app
auth
blog
cms
dev
ftp
mail
www
test
stage
staging
prod
production
portal
login
dashboard
panel
control
manage
manager
secure
secure-admin
webmail
cpanel
phpmyadmin
mysql
database
db
sql
backup
files
upload
downloads
static
assets
cdn
media
images
img
js
css
mobile
m
wap
help
support
docs
documentation
wiki
forum
community
shop
store
cart
checkout
payment
pay
billing
account
profile
user
users
member
members
client
clients
customer
customers
partner
partners
vendor
vendors
supplier
suppliers
monitor
monitoring
stats
statistics
analytics
reports
reporting
log
logs
status
health
ping
test-api
api-test
v1
v2
v3
beta
alpha
demo
sandbox
preview
temp
tmp
old
new
legacy
internal
external
public
private
intranet
extranet
vpn
remote
ssh
ftp
sftp
git
svn
jenkins
ci
cd
build
deploy
release
staging-api
prod-api
dev-api
test-db
stage-db
prod-db
EOF
        echo -e "${GREEN}${CHECKMARK} Example wordlist created: $VHOST_WORDLIST${NC}"
        echo -e "${YELLOW}${ARROW} Contains $(wc -l < "$VHOST_WORDLIST") common vhost names${NC}"
    else
        echo -e "${GREEN}${CHECKMARK} Wordlist already exists: $VHOST_WORDLIST${NC}"
    fi
}

show_usage_examples() {
    print_section "Usage Examples"
    
    echo -e "${YELLOW}Basic VHostCLI usage examples:${NC}"
    echo ""
    echo -e "${CYAN}# Basic vhost discovery with ffuf${NC}"
    echo "reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist ~/.reconcli/wordlists/vhost_common.txt"
    echo ""
    echo -e "${CYAN}# Multi-target scan with screenshots${NC}"
    echo "reconcli vhostcli --domain example.com --ip-list targets.txt --wordlist ~/.reconcli/wordlists/vhost_common.txt --screenshot"
    echo ""
    echo -e "${CYAN}# Advanced scan with AI analysis and database storage${NC}"
    echo "reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist ~/.reconcli/wordlists/vhost_common.txt --ai-mode --store-db --screenshot --verbose"
    echo ""
    echo -e "${CYAN}# Using different engines${NC}"
    echo "reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist ~/.reconcli/wordlists/vhost_common.txt --engine gobuster"
    echo "reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist ~/.reconcli/wordlists/vhost_common.txt --engine vhostfinder"
    echo ""
    echo -e "${CYAN}# With proxy (e.g., Burp Suite)${NC}"
    echo "reconcli vhostcli --domain example.com --ip 192.168.1.100 --wordlist ~/.reconcli/wordlists/vhost_common.txt --proxy http://127.0.0.1:8080"
    echo ""
}

print_completion() {
    echo -e "\n${GREEN}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${CHECKMARK} VHostCLI Dependencies Installation Complete! ${CHECKMARK}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${NC}"
    echo -e "${YELLOW}${TARGET} You can now use VHostCLI with all engines:${NC}"
    echo -e "${GREEN}  • FFUF (fast, default)${NC}"
    echo -e "${GREEN}  • Gobuster (reliable)${NC}" 
    echo -e "${GREEN}  • HTTPx (Python-based)${NC}"
    echo -e "${GREEN}  • VhostFinder (specialized)${NC}"
    echo ""
    echo -e "${YELLOW}${CAMERA} Screenshot tools available:${NC}"
    echo -e "${GREEN}  • Gowitness (default)${NC}"
    echo -e "${GREEN}  • Aquatone (alternative)${NC}"
    echo ""
    echo -e "${YELLOW}${BRAIN} Optional features:${NC}"
    echo -e "${GREEN}  • AI-powered analysis${NC}"
    echo -e "${GREEN}  • Database storage${NC}"
    echo -e "${GREEN}  • Resume functionality${NC}"
    echo ""
    echo -e "${CYAN}Run './install_vhostcli_deps.sh --examples' to see usage examples${NC}"
}

# Main execution
main() {
    print_header
    
    # Handle --examples flag
    if [[ "$1" == "--examples" ]]; then
        show_usage_examples
        exit 0
    fi
    
    # Handle --help flag
    if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
        echo "VHostCLI Dependencies Installer"
        echo ""
        echo "Usage:"
        echo "  $0                Install all dependencies"
        echo "  $0 --examples     Show usage examples"
        echo "  $0 --help        Show this help"
        echo ""
        echo "This script installs:"
        echo "  • Core engines: ffuf, gobuster, httpx"
        echo "  • VhostFinder (specialized engine)"
        echo "  • Screenshot tools: gowitness, aquatone" 
        echo "  • Optional: AI analysis, database support"
        exit 0
    fi
    
    check_prerequisites
    install_core_engines
    install_vhostfinder
    install_screenshot_tools
    install_port_scanners
    install_optional_deps
    create_wordlist_example
    verify_installation
    show_usage_examples
    print_completion
}

# Run main function with all arguments
main "$@"
