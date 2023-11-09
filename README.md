vault-unseal-yubikey
====================

Initialize and unseal a Hashicorp Vault instance using secrets encrypted by a Yubikey's PIV private key

The intent of this tool is to provide better-than-nothing encrypted storage of the root secrets for a vault cluster running on a few computers that you can easily touch during setup. Once initialized, Vault instances in the cluster can be restarted unattended without requiring operators to enter unseal secrets.

### Threat Model

:yes: Does protect against wandering hard drives. Secrets are encrypted on disk and can not be read by someone who gains access to data on said disk in the future.

:no: Does not protect against wandering Yubikeys. If someone the disk and the corresponding Yubikey, they can likely find the required PIN in the scripts or service configurations that call `vault-yubikey-helper` to unseal the local Vault instance, and use it with the Yubikey to decrypt stored root secrets for the Vault cluster.


## Usage

```
vault-yubikey-helper help
```

### Intended Workflow

1. Start the first Vault instance in a new cluster.
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
    # vault-yubikey-helper share --pin deadbeef --serial SECOND_KEY /var/data/vault/seal.json ./node2.json
    ```

    `node2.json` can be transferred to the host running your second Vault instance

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

### Run a Vault Server

```
vault server -config ./share/test-vault.hcl
```

Note that this is not developer mode, which initializes itself on startup.

## Local Build

```
make
```
