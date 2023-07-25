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

test: build
	@echo "Running tests..."
