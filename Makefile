.PHONY: all clean build test
BULID_DIR = build/bin
# Directories to create
DIRS := $(BULID_DIR)

all: clean build test

create_dirs:
	@mkdir -p $(DIRS)

clean:
	@echo "Cleaning..."
	rm -rf $(DIRS)

build: create_dirs
	@echo "Building..."
	go build -o $(BULID_DIR)/bepass cmd/bepass/main.go

release: create_dirs
	@echo "Building Release..."
	go build -ldflags '-s -w' -o $(BUILD_DIR)/bepass-release cmd/bepass/main.go

test: build
	@echo "Running tests..."

