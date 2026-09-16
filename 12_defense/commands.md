# 12 Command Notebook — Network Defense and Attack Surface Reduction

This module is the blue-team side of the lab. The offensive angle is to find services, weak access rules, or exposed paths. The defensive angle is to minimize exposure, reduce attack surface, validate logs, and confirm that risky services have been removed or restricted.

## 1) Host firewall basics

```bash
sudo ufw status verbose
sudo ufw status numbered
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw enable
```

### Offensive purpose
- Shows how a lab target can be hardened or locked down.
- Attackers use firewall checks to understand which services are reachable and which ports are blocked.

### Defensive purpose
- `ufw` is a straightforward way to reduce attack surface.
- Defenders should allow only the required ports and explicitly deny everything else.

---

## 2) nftables inspection

```bash
sudo nft list ruleset
```

### Offensive purpose
- Extracts the current firewall policy and shows how traffic is being filtered.

### Defensive purpose
- This is useful for confirming whether the host is enforcing the intended policy and whether unexpected traffic is allowed.

---

## 3) Service minimization

```bash
systemctl --type=service --state=running
sudo systemctl disable --now <service>
```

### Offensive purpose
- Attackers use service discovery to find what is running and which services are unnecessary.
- Unneeded services often create hidden risk.

### Defensive purpose
- Disable services that are not required for the system to function.
- Every unnecessary listener is an attack surface reduction opportunity.

---

## 4) Log review and evidence of abuse

```bash
journalctl --since "1 hour ago"
journalctl -p warning
journalctl -u ssh
grep -i "failed" /var/log/auth.log
```

### Offensive purpose
- Attackers read logs to understand what defenders already know and where the system is noisy or weak.

### Defensive purpose
- Defenders use this to detect failed login attempts, unauthorized access, service errors, and attack indicators.
- Logs are essential for reconstructing what happened and deciding what to change.

---

## 5) Retest exposure after the fix

```bash
ss -lntup
nmap -sV <TARGET>
```

### Defensive purpose
- Verifies whether the attack surface was reduced after the firewall or service changes.
- A proper hardening exercise compares before vs after exposure.

---

## Core defense principle
- Reduce exposure
- Log behavior
- Validate the policy
- Retest the exact same attack path

A security control is only meaningful when it is proven to stop the attack without breaking the required service.
