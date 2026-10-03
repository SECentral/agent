TAG := $(shell git describe --tags --exact-match 2>/dev/null)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
VERSION := $(if $(TAG),$(patsubst v%,%,$(TAG)),dev+$(COMMIT))
LDFLAGS := -X main.version=$(VERSION) -X main.commit=$(COMMIT)

.PHONY: all build build-all build-agent build-collector test clean

all: build-all

build: build-all

build-all: build-agent build-collector

build-agent:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/secentral-agent ./cmd/secentral-agent

build-collector:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/secentral-catalog-collector ./cmd/secentral-catalog-collector

test:
	go test ./...

clean:
	rm -rf bin
