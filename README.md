vault-unseal-yubikey
====================

Initialize and unseal a Hashicorp Vault instance using secrets encrypted by a Yubikey's PIV private key

The intent of this tool is to provide better-than-nothing encrypted storage of the root secrets for a vault cluster running on a few computers that you can easily touch during setup. Once initialized, Vault instances in the cluster can be restarted unattended without requiring operators to enter unseal secrets.

## Installation

Binaries for several architectures are published as assets on [GitHub Releases](https://github.com/jmanero/vault-yubikey-helper/releases)

The current build dynamically links several libraries to access PIV devices. These are available on macOS via homebrew, and from the default Debian and Fedora repositories:

### macOS

```
brew install yubico-piv-tool
```

### Fedora

```
dnf install yubico-piv-tool
```

### Debian

```
apt-get install libykpiv2
```

## Usage

```
vault-yubikey-helper help
```

### Intended Workflow

1. Start the first Vault instance in a new RAFT cluster.
1. Initialize it:

    ```
    # vault-yubikey-helper init /var/data/vault/seal.json
    ```

1. Unseal it:

    ```
    # vault-yubikey-helper unseal --pin deadbeef /var/data/vault/seal.json
    ```

1. Re-encrypt the new unseal-secret and root-token with a second Yubikey to add a second node to the cluster. This assumes that you have plugged a second Yubikey into the host running your first Vault instance:

    ```
    # vault-yubikey-helper share --pin deadbeef [--serial SECOND_KEY] /var/data/vault/seal.json ./share.json
    ```

    `share.json` can be transferred to the host running your second Vault instance to continue cluster provisioning.

    - The `--pin VALUE` flag or `YUBIKEY_PIN` environment variable supply a PIN for the Yubikey used to decrypt `seal.json`
    - By default, the Yubikey used to decrypt `seal.json` will be skipped when auto-selecting the second Yubikey to re-encrypt the output envelope. If you have more than two Yubikeys connected to the host, you may use the `--serial NUMBER` flag to specify the Yubikey used for encryption.

    ```
    rsync node2.json othernode:/var/data/vault/seal.json
    ```

1. Unseal a second vault instance in the cluster once you've plugged the second Yubikey, from above, into that host...

    ```
    # vault-yubikey-helper unseal --pin otherpin /var/data/vault/seal.json
    ```

### Other Uses

1. Write a temporary token to `~/.vault-token` to do more provisioning (e.g. use Terraform to create more Vault resources)
    ```
    # vault-yubikey-helper login --pin deadbeef /var/data/vault/seal.json
    # terraform plan ...
    ```

## Development

### macOS Dependencies

```
brew install pkg-config yubico-piv-tool
```

### Fedora Dependencies

```
dnf install make gcc openssl-devel pcsc-lite-devel yubico-piv-tool-devel
```

### Debian Dependencies

```
apt-get install build-essential libssl-dev libpcsclite-dev libykpiv-dev
```

### Build Locally

```
make
```

### Run a Vault Server

```
vault server -config ./share/test-vault.hcl
```

Note that this is not developer mode, which initializes itself on startup.

## Threat Model

This tool provides better-than-nothing encrypted storage of an unseal key and root token 

🟢 Does protect against wandering hard drives/data WITHOUT Yubikeys. Secrets are encrypted on disk and can not be read by someone who gains access to data on said disk in the future without the corresponding Yubikey and its PIN.

❌ Does not protect against wandering hard drives/data AND Yubikeys. If someone acquires your hard drive and the corresponding Yubikey, they can likely find the Yubikey's PIN in the scripts or service configurations that call `vault-yubikey-helper` to unseal the local Vault instance, and use it with the Yubikey to decrypt stored root secrets for the Vault cluster.
