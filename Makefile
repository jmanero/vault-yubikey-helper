## Build with host's golang toolchain bu default
.PHONY: default
default:
	go build -v -buildvcs=false -o bin/vault-yubikey-helper ./cmd

.PHONY: clean
clean:
	rm -rf bin
