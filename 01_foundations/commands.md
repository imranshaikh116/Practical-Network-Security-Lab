# 01 Command Notebook — Foundations and Lab Discipline

This module is about building a disciplined workflow. The point is not to memorize a huge toolkit; it is to know what each command tells you, how the attacker uses it, and what the defender would watch for.

## 1) Host identification and baseline

```bash
whoami
id
hostname
uname -a
cat /etc/os-release
pwd
ls -lah
find . -maxdepth 2 -type f
grep -R "pattern" .
```

### Offensive purpose
- `whoami` and `id`: confirm your current identity, permissions, and privilege level.
- `hostname` and `uname -a`: identify the system, OS, and kernel details.
- `cat /etc/os-release`: reveal distro/version info used for exploit targeting and compatibility checks.
- `ls -lah` and `find`: map the filesystem to discover relevant config files, scripts, users, and hidden structures.
- `grep -R`: search code, configs, or scripts for patterns that reveal credentials, services, or application behavior.

### Defensive purpose
- These commands establish a proper baseline for the host and help identify drift, hidden processes, suspicious files, and unexpected account activity.
- Blue teams use them to answer: what is normal on this machine, and which files or permissions changed?

---

## 2) Network identity and route knowledge

```bash
ip -br addr
ip route
ip neigh
ss -lntup
ps aux
systemctl --type=service --state=running
```

### Offensive purpose
- `ip -br addr`: shows interfaces, IPs, and whether a host is dual-stack or multi-homed.
- `ip route`: reveals the default gateway and route logic used by the machine.
- `ip neigh`: shows ARP/NDP neighbor mappings, essential in MITM and spoofing work.
- `ss -lntup`: lists listening ports and the programs bound to them. This is the first quick answer to “what is exposed?”
- `ps aux`: identifies running processes, which can reveal active services, shells, or malicious daemons.
- `systemctl --type=service --state=running`: shows which services are enabled and running.

### Defensive purpose
- These commands tell defenders which services are reachable and bound to the host.
- They help detect unexpected listeners, unauthorized processes, and configuration drift.

---

## 3) Log review and tracking the environment

```bash
journalctl --since "10 minutes ago"
```

### Offensive purpose
- Uses system logs to confirm service status, authentication attempts, and interesting behavior tied to the host.
- Attackers use it to learn what the defenders already saw and to spot the noise in the environment.

### Defensive purpose
- Logs are one of the best ways to detect unauthorized access or suspicious service startup.
- A blue team reads this to answer: what changed, who accessed the host, and when?

---

## 4) Evidence capture commands

```bash
mkdir -p ~/lab/evidence
script ~/lab/evidence/session.txt
exit
tee output.txt
```

### Why this matters
- `script` records your terminal session so you can preserve command history and forensic evidence.
- `tee` writes command output to a file while also printing it to screen.
- This is critical for red-team reporting and blue-team investigation.

### Defensive relevance
- Evidence discipline is what turns a random attack into a valid investigation.
- Without preserved commands and captures, a defender cannot reconstruct the attack chain.

---

## 5) Reconnaissance basics with Nmap

```bash
nmap -sn 192.168.56.0/24
nmap -p 22,80,443 <TARGET>
nmap -sV <TARGET>
nmap -p- <TARGET>
```

### Offensive purpose
- `nmap -sn`: ping sweep to discover live hosts on the lab segment.
- `nmap -p 22,80,443`: quick targeted port scan of likely services.
- `nmap -sV`: version detection to identify what service is running on each port.
- `nmap -p-`: full-range scan to discover all open ports.

### Defensive purpose
- Blue teams watch for unexpected scans, unusual source IPs, and port exposures.
- `nmap` output helps identify which services are visible and which ones should not be reachable.

### Important lab rule
- Always scan only your isolated VM range.
- Never scan public or external networks.

---

## Offensive + defensive mindset

Offense:
- Discover the host
- Identify the service
- Learn the version
- Hypothesize the risk
- Validate with controlled evidence

Defense:
- Reduce exposure
- Control allowed ports
- Detect scan behavior
- Log access and changes
- Verify only expected services are running

The real skill in this module is not “run nmap”. It is “read the result and explain the exposure.”
