# Build the Range

## Network

Create a Host-Only or Internal virtual network.

Example:

```text
192.168.56.0/24
```

Do not attach deliberately vulnerable machines directly to your normal LAN.

## VMs

### Kali
Use it as the primary assessment machine.

### Router VM
Use OpenWrt or another router image.

### Linux server
Use Ubuntu/Debian.

### Vulnerable target
Metasploitable 2 is useful for old-service exploitation.

### Web targets
Juice Shop, DVWA and WebGoat are useful for application testing.

## Snapshot plan

Create:

```text
clean
services-installed
vulnerable
pre-attack
post-defense
```

If a lab gets broken, revert rather than spending an hour trying to undo every experiment.

## Optional Internet adapter

If you need Internet access to install packages:

1. Add a temporary NAT adapter.
2. Update/install packages.
3. Shut down the VM.
4. Remove/disconnect the NAT adapter.
5. Start the attack lab with only the isolated adapter.

This avoids the classic mistake of putting an intentionally vulnerable VM on a real network.
