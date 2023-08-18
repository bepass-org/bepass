.PHONY: all clean build test
BUILD_DIR = build/bin
# Directories to create
DIRS := $(BUILD_DIR)

all: clean build test

create_dirs:
	@mkdir -p $(DIRS)

clean:
	@echo "Cleaning..."
	rm -rf $(DIRS)

build: create_dirs
	@echo "Building Cli Version..."
	CGO_ENABLED=0 go build -trimpath -o $(BUILD_DIR)/bepass cmd/cli/main.go

release: create_dirs
	@echo "Building Cli Release Version..."
	CGO_ENABLED=0 go build -ldflags '-s -w' -trimpath -o $(BUILD_DIR)/bepass cmd/cli/main.go

gui: create_dirs
	@echo "Building GUI version..."
	go build -trimpath -o $(BUILD_DIR)/bepass-gui cmd/gui/gui.go

gui-release: create_dirs
	@echo "Building GUI Release Version..."
	go build -ldflags '-s -w' -trimpath -o $(BUILD_DIR)/bepass-gui cmd/gui/gui.go

test: build
	@echo "Running tests..."
	# Later's some test cases would be added
