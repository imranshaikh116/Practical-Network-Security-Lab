# 04 Command Notebook — Router Filtering, MAC Trust, and Local Identity

This module is about the weakness of trusting a local identity too much. A MAC address is useful for local delivery, but it is not a strong cryptographic identity. The offensive angle is to change the identity and see whether the router policy follows it. The defensive angle is to recognize that identity-based filtering alone is weak unless combined with stronger network controls.

## 1) Inspect interface identity and local routing

```bash
ip -br link
ip link show eth0
ip addr
ip route
```

### Offensive purpose
- `ip link show` reveals the current NIC and MAC address.
- `ip addr` shows the interface configuration.
- `ip route` confirms the path used by the host.

### Defensive purpose
- This gives the baseline for the client and router so that later identity changes are visible.
- If MAC values unexpectedly change, defenders can investigate whether a rogue machine is pretending to be an approved one.

---

## 2) Change the local MAC in a lab-only environment

```bash
sudo ip link set dev eth0 down
sudo ip link set dev eth0 address 02:11:22:33:44:55
sudo ip link set dev eth0 up
```

### Offensive purpose
- This simulates a device impersonating an approved host.
- If the router is filtering only by MAC, the device may be accepted despite the identity change.

### Defensive purpose
- Blue teams use this to validate whether a router or switch is relying on a weak identifier rather than a strong authenticated policy.
- It also helps document how poor access controls can be bypassed.

### Lab safety
- Perform this only on a disposable lab NIC.
- Restore via snapshot or revert the MAC immediately after the exercise.

---

## 3) Observe whether the network reacts to the changed identity

```bash
ip neigh
sudo tcpdump -i any -nn arp
sudo tcpdump -i any -nn 'udp port 67 or udp port 68'
```

### Offensive purpose
- `ip neigh` shows how the host maps IPs to MAC addresses after the change.
- `arp` capture shows whether the network is seeing a new identity.
- DHCP traffic reveals how the client obtains network parameters after the change.

### Defensive purpose
- These commands show whether the network can detect a spoofed or unauthorized identity.
- A defender can ask: is the router logging the new MAC, and does DHCP show an unexpected client?

---

## Defensive controls to compare

- Strong authentication to router management
- VLAN segmentation and network isolation
- DHCP snooping and port security on switches
- MAC binding only as a weak convenience control, not as primary identity
- Logging of MAC and lease changes

### Critical takeaway
- A MAC address is a local link-layer identifier, not a trustworthy user identity.
- If a policy uses only MAC allowlists, it is easy to bypass when the attacker changes the device state or spoofs a local address.
