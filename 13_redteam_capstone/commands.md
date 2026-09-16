# 13 Command Notebook — Red Team Capstone and Detection Engineering

This final module ties everything together: recon, exploitation, privilege escalation, evidence collection, and the defender’s response. The offensive angle is to move through the full attack chain in a deliberate and documented way. The defensive angle is to identify the earliest suspicious event and build a timeline from evidence.

## 1) Reconnaissance phase

```bash
nmap -sn 192.168.56.0/24
nmap -p- <TARGET>
nmap -sV <TARGET>
```

### Offensive purpose
- `nmap -sn` finds live hosts.
- `nmap -p-` reveals all open ports.
- `nmap -sV` identifies the services and versions that might be targeted.

### Defensive purpose
- Blue teams use this to understand what an attacker sees first and where the attack path begins.
- A scan is often the first sign of hostile activity.

---

## 2) Post-compromise local enumeration

```bash
whoami
id
hostname
uname -a
ip addr
ip route
ss -lntup
ps aux
sudo -l
find / -perm -4000 -type f 2>/dev/null
```

### Offensive purpose
- Confirms the foothold and environment.
- `sudo -l` reveals whether privilege escalation is possible.
- `find / -perm -4000` helps identify SUID binaries that may be abused.
- `ps aux` shows running processes and suspicious activity.

### Defensive purpose
- This is the point where defenders look for unusual shells, unexpected child processes, privilege changes, or abnormal local enumeration commands.

---

## 3) Lateral movement within the lab

```bash
ssh labuser@192.168.56.30
```

### Offensive purpose
- Tests whether access to one host can be reused to reach another in the lab network.

### Defensive purpose
- Blue teams check whether trust relationships, shared credentials, or weak SSH configuration allowed the pivot.

---

## 4) Evidence capture and timeline building

```bash
journalctl --since "1 hour ago"
sudo tcpdump -i any -nn -w ~/lab/13_capstone.pcap
```

### Offensive purpose
- Preserves the full attack evidence for reporting and reflection.
- Helps you connect a sequence of events into a story.

### Defensive purpose
- Logs and packet captures are the foundation of detection engineering and incident response.
- A defender reconstructs the path from scan → exploit → access → privilege escalation → pivot.

---

## 5) Exploit module validation reminder

```bash
msfconsole
search <term>
info <module>
use <module>
set RHOSTS <TARGET>
check
run
```

### Offensive purpose
- Makes the exploit workflow explicit and disciplined.
- This ensures the attacker tests the vulnerability before triggering the payload.

### Defensive purpose
- Blue teams understand that the same exploit modules can be used to test a service and to identify possible attack paths.

---

## Final discipline

The capstone is not about “getting a shell.” It is about proving the attack path, explaining the evidence, and making the defender’s response stronger.

### Good red-team output includes:
- time of recon
- service version and exposure
- initial access point
- privilege level gained
- lateral movement path
- evidence collected
- control added to stop the same chain

### Good blue-team output includes:
- first suspicious event
- source and destination
- time and method of access
- which account was used
- what process or service was abused
- which rule or control would have blocked it

### Key lesson
- Every technique in this course is stronger when you can explain both how to do it and how to detect or stop it.
