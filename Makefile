BINARY  := netscan
PKG     := ./cmd/netscan
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all build test race cover vet fmt lint golden clean

all: vet test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

# The race detector needs cgo (a C compiler) on the build machine.
race:
	CGO_ENABLED=1 go test -race ./...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vet:
	go vet ./...

fmt:
	gofmt -s -w .

lint:
	golangci-lint run

# Regenerate report golden files after an intentional output change.
golden:
	go test ./internal/report -update

clean:
	rm -rf bin dist coverage.out
