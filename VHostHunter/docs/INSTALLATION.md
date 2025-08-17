# 🎯 VHostHunter Installation Guide

## Prerequisites

### System Requirements
- **Python 3.8+**
- **Go 1.19+** (for Go-based tools)
- **Git** (for tool installation)
- **Linux/macOS** (Windows with WSL2)

### Network Requirements
- Internet access for tool installation
- Target network accessibility
- Optional: Proxy support for Burp Suite integration

## Automated Installation

### Quick Install (Recommended)
```bash
# Install all dependencies automatically
./install_dependencies.sh

# Verify installation
./check_dependencies.sh
```

### What Gets Installed

#### Core Engines
- **FFUF** - Fast web fuzzer (Go)
- **Gobuster** - Directory/vhost bruteforcer (Go)
- **HTTPx** - HTTP toolkit (Python)
- **VhostFinder** - Specialized engine (Go)

#### Port Scanners
- **Naabu** - Fast port scanner (Go)
- **JFScan** - Advanced scanner with masscan wrapper (Python)
- **Nmap** - Network mapper (system package)
- **Masscan** - Ultra-fast port scanner (system package)

#### Security Tools
- **Nuclei** - Vulnerability scanner (Go)
- **Gowitness** - Screenshot tool (Go)
- **Aquatone** - Alternative screenshot tool (Go)

#### Python Dependencies
- **click** - CLI framework
- **httpx** - HTTP client library
- **requests** - HTTP library
- **rich** - Terminal formatting
- **sqlalchemy** - Database support
- **openai** - AI analysis (optional)

## Manual Installation

### Install Go Tools
```bash
# Core engines
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Port scanners
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Screenshot tools
go install github.com/sensepost/gowitness@latest
go install github.com/michenriksen/aquatone@latest
```

### Install Python Dependencies
```bash
pip install click httpx requests rich sqlalchemy openai jfscan
```

### Install System Packages
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install nmap masscan git

# CentOS/RHEL
sudo yum install nmap masscan git

# macOS
brew install nmap masscan git
```

### Install VhostFinder
```bash
git clone https://github.com/wdahlenburg/VhostFinder.git
cd VhostFinder
go build -o VhostFinder
sudo cp VhostFinder /usr/local/bin/
```

## Configuration

### Environment Setup
```bash
# Add Go tools to PATH
export PATH=$PATH:$(go env GOPATH)/bin

# Create config directory
mkdir -p ~/.vhosthunter

# Create default config
cat > ~/.vhosthunter/config.json << EOF
{
    "default_engine": "ffuf",
    "default_rate_limit": 100,
    "default_timeout": 10,
    "default_retries": 3,
    "cache_enabled": true,
    "cache_ttl": 86400
}
EOF
```

### API Keys (Optional)
```bash
# For AI analysis
export OPENAI_API_KEY="your-api-key"

# For notifications
export SLACK_WEBHOOK="your-webhook-url"
export DISCORD_WEBHOOK="your-webhook-url"
```

## Verification

### Check Installation
```bash
./check_dependencies.sh
```

### Test Basic Functionality
```bash
# Simple test with localhost
./vhosthunter --domain localhost --ip 127.0.0.1 --wordlist wordlists/common.txt --verbose
```

### Expected Output
```
🔍 VHostHunter Dependencies Status Check
════════════════════════════════════════════════════════════════

Core Virtual Host Discovery Engines:
──────────────────────────────────────
✅ FFUF (Fast web fuzzer)
✅ Gobuster (Directory/vhost bruteforcer)
✅ HTTPx (Python HTTP toolkit)
✅ VhostFinder (installed at /usr/local/bin/)

Port Scanners (for discovery):
──────────────────────────────
✅ Naabu (Fast port scanner)
✅ JFScan (Advanced masscan wrapper)
✅ Nmap (Network mapper)
✅ Masscan (Fast port scanner)

🎉 ALL DEPENDENCIES SATISFIED! VHostHunter is ready to use! 🎉
```

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Fix permissions
chmod +x vhosthunter hunt.sh install_dependencies.sh check_dependencies.sh
```

#### Go Tools Not Found
```bash
# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

#### Python Module Not Found
```bash
# Install missing modules
pip install --upgrade click httpx requests rich sqlalchemy
```

#### VhostFinder Build Failed
```bash
# Manual build with verbose output
cd VhostFinder
go build -v -o VhostFinder
```

### System-Specific Issues

#### Ubuntu/Debian
```bash
# Update package list
sudo apt update

# Install build essentials
sudo apt install build-essential

# Install Go if not available
sudo apt install golang-go
```

#### CentOS/RHEL
```bash
# Install development tools
sudo yum groupinstall "Development Tools"

# Install Go
sudo yum install golang
```

#### macOS
```bash
# Install Xcode command line tools
xcode-select --install

# Install Homebrew if not available
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

## Performance Optimization

### System Tuning
```bash
# Increase file descriptor limits
ulimit -n 65535

# Optimize network settings
echo 'net.core.rmem_max = 134217728' | sudo tee -a /etc/sysctl.conf
echo 'net.core.rmem_default = 134217728' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Tool-Specific Settings
```bash
# FFUF optimization
export FFUF_MAXTHREADS=100

# Nuclei optimization
export NUCLEI_TEMPLATES_DIRECTORY=~/.nuclei-templates
```

## Next Steps

After successful installation:

1. **Read the usage guide**: [EXAMPLES.md](EXAMPLES.md)
2. **Configure your environment**: Set API keys, proxy settings
3. **Test with safe targets**: Use intentionally vulnerable applications
4. **Join the community**: Share findings and improvements

## Support

If you encounter issues:

1. Check the troubleshooting section above
2. Verify system requirements
3. Run `./check_dependencies.sh` for diagnostic info
4. Open an issue with detailed error messages

---

**Happy hunting! 🎯**
