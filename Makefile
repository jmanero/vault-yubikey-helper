## Linux build architectures
PLATFORMS += linux_amd64
PLATFORMS += linux_arm64

BINARIES = $(PLATFORMS:%=bin/vault-yubikey-helper-%)
SOURCES  = $(shell find . -name '*.go') go.mod go.sum
PACKAGES := build-essential libssl-dev libpcsclite-dev libykpiv-dev

GOOS   = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

## Build with host's golang toolchain bu default
.PHONY: default
default: bin/vault-yubikey-helper-$(GOOS)_$(GOARCH)

## Run cross-architecture builds in docker containers using the golang:bookworm image
multiarch: $(BINARIES)

.PHONY: clean
clean:
	rm -rf bin

## Build with host toolchain
bin/vault-yubikey-helper-$(GOOS)_$(GOARCH): $(SOURCES)
	mkdir -p $(@D)
	CGO=1 go build -o $@ .

## Cross-architecture linux builds
bin/vault-yubikey-helper-%: $(SOURCES)
	mkdir -p $(@D)
	docker run --rm --platform $(subst  _,/,$*) --volume $(CURDIR):/work --workdir /work --env CGO=1 golang:bookworm bash -c 'apt-get update && apt-get install -y $(PACKAGES) && go build -buildvcs=false -o $@ .'
