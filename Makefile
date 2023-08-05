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
	@echo "Building..."
	go build -o $(BUILD_DIR)/bepass cmd/cli/main.go

release: create_dirs
	@echo "Building Release..."
	go build -ldflags '-s -w' -o $(BUILD_DIR)/bepass cmd/cli/main.go

test: build
	@echo "Running tests..."

