# Makefile for ReconCLI Web UI

.PHONY: help build run clean test deps dev prod docker

# Variables
BINARY_NAME=reconcli-webui
BUILD_DIR=./bin
SRC_DIR=.
MAIN_FILE=main.go

# Default target
help: ## Show this help message
	@echo "ReconCLI Web UI - Available commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

# Setup and dependencies
deps: ## Download dependencies
	@echo "📦 Installing Go dependencies..."
	go mod download
	go mod tidy

init: ## Initialize project (create directories, copy env file)
	@echo "🚀 Initializing ReconCLI Web UI..."
	mkdir -p data uploads logs
	@if [ ! -f .env ]; then \
		echo "📋 Creating .env file from template..."; \
		cp .env.example .env; \
		echo "⚠️  Please edit .env file with your configuration"; \
	fi
	@echo "✅ Initialization complete!"

# Development
dev: deps ## Run in development mode with hot reload
	@echo "🔥 Starting development server..."
	go run $(MAIN_FILE)

run: ## Run the application
	@echo "🚀 Starting ReconCLI Web UI..."
	go run $(MAIN_FILE)

# Build
build: deps ## Build the application
	@echo "🔨 Building $(BINARY_NAME)..."
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) $(MAIN_FILE)
	@echo "✅ Build complete: $(BUILD_DIR)/$(BINARY_NAME)"

build-linux: deps ## Build for Linux
	@echo "🔨 Building for Linux..."
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-linux $(MAIN_FILE)

build-windows: deps ## Build for Windows
	@echo "🔨 Building for Windows..."
	mkdir -p $(BUILD_DIR)
	GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-windows.exe $(MAIN_FILE)

build-mac: deps ## Build for macOS
	@echo "🔨 Building for macOS..."
	mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/$(BINARY_NAME)-darwin $(MAIN_FILE)

build-all: build-linux build-windows build-mac ## Build for all platforms

# Testing
test: ## Run tests
	@echo "🧪 Running tests..."
	go test -v ./...

test-coverage: ## Run tests with coverage
	@echo "📊 Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

# Production
prod: build ## Build and run in production mode
	@echo "🚀 Starting production server..."
	ENVIRONMENT=production $(BUILD_DIR)/$(BINARY_NAME)

# Database operations
db-reset: ## Reset database (delete and recreate)
	@echo "🗄️ Resetting database..."
	rm -f data/reconcli_webui.db
	@echo "✅ Database reset complete"

db-backup: ## Backup database
	@echo "💾 Backing up database..."
	mkdir -p backups
	cp data/reconcli_webui.db backups/reconcli_webui_$(shell date +%Y%m%d_%H%M%S).db
	@echo "✅ Database backup complete"

# Cleanup
clean: ## Clean build artifacts
	@echo "🧹 Cleaning up..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html
	@echo "✅ Cleanup complete"

clean-all: clean ## Clean everything including uploads and database
	@echo "🧹 Cleaning everything..."
	rm -rf uploads/* data/* logs/*
	@echo "✅ Full cleanup complete"

# Docker operations (for future use)
docker-build: ## Build Docker image
	@echo "🐳 Building Docker image..."
	docker build -t reconcli-webui:latest .

docker-run: ## Run Docker container
	@echo "🐳 Running Docker container..."
	docker run -p 8080:8080 -v $(PWD)/data:/app/data -v $(PWD)/uploads:/app/uploads reconcli-webui:latest

# Security
security-check: ## Run security checks
	@echo "🔒 Running security checks..."
	@if command -v gosec >/dev/null 2>&1; then \
		gosec ./...; \
	else \
		echo "⚠️  gosec not installed. Install with: go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest"; \
	fi

# Formatting and linting
fmt: ## Format Go code
	@echo "📐 Formatting code..."
	go fmt ./...

lint: ## Run linter
	@echo "🔍 Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "⚠️  golangci-lint not installed. Install from: https://golangci-lint.run/usage/install/"; \
	fi

# Installation
install: build ## Install binary to system
	@echo "📦 Installing $(BINARY_NAME)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/
	@echo "✅ Installed to /usr/local/bin/$(BINARY_NAME)"

uninstall: ## Uninstall binary from system
	@echo "🗑️ Uninstalling $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)
	@echo "✅ Uninstalled"

# Quick setup for development
setup: init deps ## Complete setup for development
	@echo "🎯 Development setup complete!"
	@echo ""
	@echo "Next steps:"
	@echo "1. Edit .env file with your configuration"
	@echo "2. Run 'make dev' to start development server"
	@echo "3. Open http://localhost:8080 in your browser"

# Show project status
status: ## Show project status
	@echo "📊 ReconCLI Web UI Status:"
	@echo ""
	@echo "📁 Project structure:"
	@ls -la
	@echo ""
	@echo "📦 Go modules:"
	@go list -m all | head -10
	@echo ""
	@echo "🗄️ Database:"
	@if [ -f data/reconcli_webui.db ]; then \
		echo "  ✅ Database exists"; \
		echo "  📊 Size: $$(du -h data/reconcli_webui.db | cut -f1)"; \
	else \
		echo "  ❌ Database not found"; \
	fi
	@echo ""
	@echo "📁 Upload directory:"
	@if [ -d uploads ]; then \
		echo "  ✅ Upload directory exists"; \
		echo "  📊 Files: $$(find uploads -type f | wc -l)"; \
	else \
		echo "  ❌ Upload directory not found"; \
	fi
