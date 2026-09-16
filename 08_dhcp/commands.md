# 08 Command Notebook — DHCP: Lease Manipulation and Rogue Server Abuse

DHCP is a protocol that gives a client critical network identity information: IP, gateway, DNS, and lease details. The offensive angle is to force the client to accept a rogue offer or manipulate the lease. The defensive angle is to detect unexpected DHCP servers and validate that the client receives the expected network configuration.

## 1) Observe DHCP traffic

```bash
sudo tcpdump -i any -nn -vv 'udp port 67 or udp port 68'
```

### Offensive purpose
- Captures the DHCP DORA sequence: Discover, Offer, Request, Acknowledge.
- Lets you see how a client picks a lease and which server responds first.

### Defensive purpose
- A defender can see whether the client is receiving more than one valid offer or whether an unexpected server is responding.
- This is critical in detecting rogue DHCP attacks.

---

## 2) Inspect client network identity after a lease

```bash
ip addr
ip route
resolvectl status
```

### Offensive purpose
- Shows whether the client accepted the lease and what gateway/DNS values it is using.

### Defensive purpose
- This is how a defender verifies the host has the expected IP, default route, and DNS settings.
- If gateway or DNS suddenly changes after a lease renew, that is a strong indicator of malicious DHCP behavior.

---

## 3) Force a DHCP lease renewal

```bash
sudo dhclient -v
sudo dhclient -r
sudo dhclient
```

### Offensive purpose
- Force a client to request a new lease so you can test whether it accepts a rogue DHCP server.
- Useful when verifying how fast or how widely the client trusts a DHCP response.

### Defensive purpose
- Defenders can use this to test the network under controlled conditions and confirm whether rogue DHCP servers are being blocked.

### Important note
- The exact command varies by distro and whether NetworkManager or another DHCP client is in use.
- Keep all testing on an isolated L2 network.

---

## Defensive controls to test

- DHCP snooping on switches
- Port security and trusted interface policy
- VLAN segmentation
- Monitoring for unexpected DHCP offer sources
- Verification of gateway and DNS after renewal

### Key lesson
- DHCP gives routing and DNS instructions; if those instructions are wrong, the client may be silently redirected even though it still has connectivity.
