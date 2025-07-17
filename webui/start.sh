#!/bin/bash

# ReconCLI Web UI Start Script
# This script helps you start the ReconCLI Web UI with proper setup

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Print banner
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    ReconCLI Web UI                           ║"
    echo "║            Advanced Reconnaissance Toolkit                  ║"
    echo "║                  Web Interface                               ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print colored messages
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Go is installed
check_go() {
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed. Please install Go 1.21 or higher."
        echo "Visit: https://golang.org/doc/install"
        exit 1
    fi

    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    log_success "Go version $GO_VERSION detected"
}

# Check if required directories exist
check_directories() {
    log_info "Checking directory structure..."

    for dir in "data" "uploads" "web/templates"; do
        if [ ! -d "$dir" ]; then
            log_info "Creating directory: $dir"
            mkdir -p "$dir"
        fi
    done

    log_success "Directory structure verified"
}

# Check if .env file exists
check_env() {
    if [ ! -f ".env" ]; then
        log_warning ".env file not found"
        if [ -f ".env.example" ]; then
            log_info "Creating .env file from template..."
            cp .env.example .env
            log_success ".env file created"
            log_warning "Please edit .env file with your configuration before starting"
        else
            log_error ".env.example file not found. Cannot create configuration."
            exit 1
        fi
    else
        log_success ".env file found"
    fi
}

# Install dependencies
install_deps() {
    log_info "Installing Go dependencies..."
    if go mod download && go mod tidy; then
        log_success "Dependencies installed successfully"
    else
        log_error "Failed to install dependencies"
        exit 1
    fi
}

# Check if database exists
check_database() {
    if [ -f "data/reconcli_webui.db" ]; then
        log_success "Database file exists"
    else
        log_info "Database will be created on first run"
    fi
}

# Start the application
start_app() {
    log_info "Starting ReconCLI Web UI..."
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║  🌐 ReconCLI Web UI will be available at:                   ║${NC}"
    echo -e "${CYAN}║     http://localhost:8080                                    ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║  🔑 Default Login Credentials:                              ║${NC}"
    echo -e "${CYAN}║     Username: admin                                          ║${NC}"
    echo -e "${CYAN}║     Password: admin123                                       ║${NC}"
    echo -e "${CYAN}║                                                              ║${NC}"
    echo -e "${CYAN}║  ⚠️  IMPORTANT: Change the password after first login!      ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to stop the server${NC}"
    echo ""

    if go run main.go; then
        log_success "Application started successfully"
    else
        log_error "Failed to start application"
        exit 1
    fi
}

# Display help
show_help() {
    echo "ReconCLI Web UI Start Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message"
    echo "  -c, --check     Check system requirements only"
    echo "  -s, --setup     Setup only (no start)"
    echo "  -d, --dev       Development mode"
    echo "  -b, --build     Build the application"
    echo "  --reset-db      Reset database"
    echo "  --clean         Clean build artifacts"
    echo ""
    echo "Examples:"
    echo "  $0              # Normal start"
    echo "  $0 --check     # Check requirements"
    echo "  $0 --setup     # Setup only"
    echo "  $0 --dev       # Development mode"
}

# Setup only
setup_only() {
    log_info "Setting up ReconCLI Web UI..."
    check_go
    check_directories
    check_env
    install_deps
    check_database
    log_success "Setup complete! Run '$0' to start the application."
}

# Check only
check_only() {
    log_info "Checking system requirements..."
    check_go
    check_directories

    if [ -f ".env" ]; then
        log_success ".env file exists"
    else
        log_warning ".env file missing"
    fi

    check_database
    log_success "System check complete"
}

# Reset database
reset_database() {
    log_warning "This will delete all data in the database!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f "data/reconcli_webui.db" ]; then
            rm -f data/reconcli_webui.db
            log_success "Database reset complete"
        else
            log_info "Database file not found, nothing to reset"
        fi
    else
        log_info "Database reset cancelled"
    fi
}

# Clean build artifacts
clean_build() {
    log_info "Cleaning build artifacts..."
    rm -rf bin/
    rm -f coverage.out coverage.html
    log_success "Cleanup complete"
}

# Build application
build_app() {
    log_info "Building ReconCLI Web UI..."
    if make build; then
        log_success "Build complete: bin/reconcli-webui"
    else
        log_error "Build failed"
        exit 1
    fi
}

# Main execution
main() {
    print_banner

    case "${1:-}" in
        -h|--help)
            show_help
            ;;
        -c|--check)
            check_only
            ;;
        -s|--setup)
            setup_only
            ;;
        -d|--dev)
            log_info "Starting in development mode..."
            setup_only
            ENVIRONMENT=development start_app
            ;;
        -b|--build)
            build_app
            ;;
        --reset-db)
            reset_database
            ;;
        --clean)
            clean_build
            ;;
        "")
            # Normal start
            setup_only
            start_app
            ;;
        *)
            log_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
