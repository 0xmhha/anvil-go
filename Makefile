.PHONY: all build test lint clean install run help

# Variables
BINARY_NAME=anvil
BUILD_DIR=./build
CMD_DIR=./cmd/anvil
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

# Go commands
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOFMT=$(GOCMD) fmt
GOVET=$(GOCMD) vet

# Default target
all: lint test build

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_DIR)

# Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

# Run tests with coverage report
test-coverage: test
	@echo "Generating coverage report..."
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

# Run linter
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not installed, running go vet..."; \
		$(GOVET) ./...; \
	fi

# Format code
fmt:
	@echo "Formatting code..."
	$(GOFMT) ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(BUILD_DIR)
	@rm -f coverage.out coverage.html

# Install binary
install: build
	@echo "Installing $(BINARY_NAME)..."
	@cp $(BUILD_DIR)/$(BINARY_NAME) $(GOPATH)/bin/

# Run the application
run: build
	@echo "Running $(BINARY_NAME)..."
	$(BUILD_DIR)/$(BINARY_NAME)

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

# Generate mocks (if using mockery)
mocks:
	@echo "Generating mocks..."
	@if command -v mockery >/dev/null 2>&1; then \
		mockery --all --dir=./pkg --output=./internal/mocks; \
	else \
		echo "mockery not installed, skipping..."; \
	fi

# Run benchmarks
bench:
	@echo "Running benchmarks..."
	$(GOTEST) -bench=. -benchmem ./...

# Run e2e tests
e2e: build
	@echo "Running e2e tests..."
	$(GOTEST) -v ./test/e2e/...

# Show help
help:
	@echo "Anvil-Go Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make              Build after running lint and tests"
	@echo "  make build        Build the binary"
	@echo "  make test         Run tests"
	@echo "  make test-coverage Run tests with coverage report"
	@echo "  make lint         Run linter"
	@echo "  make fmt          Format code"
	@echo "  make clean        Clean build artifacts"
	@echo "  make install      Install binary to GOPATH/bin"
	@echo "  make run          Build and run"
	@echo "  make deps         Download dependencies"
	@echo "  make mocks        Generate mocks"
	@echo "  make bench        Run benchmarks"
	@echo "  make e2e          Run e2e tests"
	@echo "  make help         Show this help"
