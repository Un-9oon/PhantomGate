# PhantomGate — Build Targets
# ────────────────────────────

BINARY=phantomgate
VERSION=1.0.0
BUILD_DIR=bin
SRC=./cmd/phantomgate

LDFLAGS=-ldflags "-s -w -X main.Version=$(VERSION)"

.PHONY: all build linux windows mac clean deps test list

all: deps build

deps:
	go mod tidy

build:
	@echo "⚡ Building PhantomGate $(VERSION)..."
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(SRC)
	@echo "✓ Build complete: $(BUILD_DIR)/$(BINARY)"

linux:
	@echo "⚡ Building for Linux (amd64)..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-linux-amd64 $(SRC)
	@echo "✓ $(BUILD_DIR)/$(BINARY)-linux-amd64"

windows:
	@echo "⚡ Building for Windows (amd64)..."
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-windows-amd64.exe $(SRC)
	@echo "✓ $(BUILD_DIR)/$(BINARY)-windows-amd64.exe"

mac:
	@echo "⚡ Building for macOS (amd64)..."
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 $(SRC)
	@echo "✓ $(BUILD_DIR)/$(BINARY)-darwin-amd64"

cross: linux windows mac
	@echo "✓ All cross-platform builds complete."

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./... -v

list:
	go run $(SRC) --list --phishlet-dir phishlets
