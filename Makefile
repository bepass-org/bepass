.PHONY: all clean build test
BUILD_DIR = build/bin
# Directories to create
DIRS := $(BUILD_DIR)

# Clean build artifacts and run tests
all: clean build test

# Create necessary directories
create_dirs:
	@mkdir -p $(DIRS)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(DIRS)

# Build the CLI version
build: create_dirs
	@echo "Building CLI Version..."
	CGO_ENABLED=0 go build -trimpath -o $(BUILD_DIR)/bepass cmd/cli/main.go

# Build the CLI release version (stripped and with ldflags)
release: create_dirs
	@echo "Building CLI Release Version..."
	CGO_ENABLED=0 go build -ldflags '-s -w' -trimpath -o $(BUILD_DIR)/bepass cmd/cli/main.go

# Build the GUI version
gui: create_dirs
	@echo "Building GUI version..."
	go build -trimpath -o $(BUILD_DIR)/bepass-gui cmd/gui/main.go

# Build the GUI release version (stripped and with ldflags)
gui-release: create_dirs
	@echo "Building GUI Release Version..."
	go build -ldflags '-s -w' -trimpath -o $(BUILD_DIR)/bepass-gui cmd/gui/main.go

# Build and run tests
test: build
	@echo "Running tests..."
	go test $(shell go list ./... | grep -vE 'cmd/mobile')
