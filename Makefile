# Network Watcher - Build Automation

.PHONY: all build clean generate run test lint help

all: generate build

generate:
	@echo "Generating eBPF bindings..."
	go generate ./...

build: generate
	@echo "Building webui..."
	go build -o bin/webui ./cmd/webui

build-quick:
	go build -o bin/webui ./cmd/webui

run: build
	sudo ./bin/webui

test:
	go test -v -race ./pkg/...

coverage:
	go test -coverprofile=coverage.out ./pkg/...
	go tool cover -html=coverage.out -o coverage.html

lint:
	golangci-lint run ./...

clean:
	rm -rf bin/ coverage.out coverage.html
	rm -f pkg/collector/*_bpfel.go pkg/collector/*_bpfeb.go pkg/collector/*.o

deps:
	go mod tidy && go mod download

check-tools:
	@which clang > /dev/null || echo "Install clang"
	@which llvm-strip > /dev/null || echo "Install llvm"
	@echo "Tools OK"

help:
	@echo "Network Watcher"
	@echo ""
	@echo "  make build   - Build the webui binary"
	@echo "  make run     - Build and run (requires root)"
	@echo "  make test    - Run unit tests"
	@echo "  make lint    - Run linter"
	@echo "  make clean   - Remove build artifacts"
	@echo "  make deps    - Install dependencies"
