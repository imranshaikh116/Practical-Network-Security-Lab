# 13 — Red Team Capstone: Full Attack Chain, Evidence, and Defensive Response

## Concept first: real attacks are chains, not isolated tricks

The capstone combines everything from recon to privilege escalation to lateral movement. Success is not a single exploit; it is a sequence of events that leads to an objective while leaving enough evidence to explain the path and improve detection.

### Offensive angle

The red team treats the network as a target graph. It begins with discovery, enumerates opportunities, validates the weakest path, gains footholds, escalates privileges, and looks for lateral movement. It is about reaching a goal while understanding the constraints and noise of the environment.

### Defensive angle

The blue team watches the same path in reverse. Where are the first suspicious events? Which process changed? Which account was used? What artifacts can be preserved? This is where detection engineering and incident response become essential.

### Commands explained

- `nmap` and `curl`/`ssh`/`dig`: use reconnaissance and verification to map the service surface.
- `sudo -l`, `find / -perm -4000 ...`, and `find /etc /opt /var/www ...`: look for privilege-escalation or trust weaknesses. 
- `journalctl`, `ss -ant`, `ip neigh`, and `tcpdump`: collect evidence for detection and timeline reconstruction.
- The final step is not just to exploit; it is to produce a clear chain of events and connect each step to a defense or detection control.

The capstone teaches the real discipline of adversary emulation: prove the path, document the evidence, and turn the result into a better control.

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

## Stop thinking in isolated tricks

A red team normally wants a path.

For your VM range, build:

```text
Kali
  |
  v
Router
  |
  +---- Web server
  |
  +---- Linux server
  |
  +---- Vulnerable VM
```

Add a separate management network if your hypervisor supports it.

## Stage 1 — Recon

```bash
nmap -sn 192.168.56.0/24
nmap -p- <TARGET>
nmap -sV <TARGET>
```

Record every finding.

## Stage 2 — Enumeration

For each service ask:

```text
What is it?
What version?
What account model?
What data?
What trust relationship?
What configuration?
What logs?
```

Examples:

```bash
curl -I http://<TARGET>/
ssh -v user@<TARGET>
dig @192.168.56.30 web.lab.test
```

## Stage 3 — Initial access

Choose one intentionally vulnerable service from your lab.

Prove access with the smallest useful action.

For a shell:

```bash
whoami
id
hostname
```

Do not start destructive behavior.

## Stage 4 — Situational awareness

Once inside a lab VM:

```bash
id
uname -a
ip addr
ip route
ss -lntup
ps aux
```

Look for trust relationships rather than immediately trying random privilege-escalation commands.

## Stage 5 — Privilege escalation

Use a deliberately vulnerable VM and study the cause of the weakness.

Common categories:

- weak sudo configuration
- writable scripts executed by privileged users
- insecure file permissions
- vulnerable SUID programs
- exposed secrets
- outdated kernel/software
- cron jobs with unsafe permissions

A useful manual start:

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
find /etc /opt /var/www -type f -writable 2>/dev/null | head -100
```

Do not treat every result as exploitable. Trace how the file or permission is actually used.

## Stage 6 — Lateral movement

Create two disposable servers with intentionally shared lab credentials or a deliberately weak trust relationship.

Prove that access to one machine can lead to another.

For example, use a test SSH account:

```bash
ssh labuser@192.168.56.30
```

Then fix the trust relationship and verify the path disappears.

## Stage 7 — Detection

The blue team should see:

```text
Discovery
Initial access
Command execution
Authentication
Lateral movement
```

Collect:

```bash
journalctl --since "1 hour ago"
ss -ant
ip neigh
```

Capture traffic where useful:

```bash
sudo tcpdump -i any -nn -w ~/lab/13_capstone.pcap
```

## Stage 8 — Write the attack story

A strong red-team report is a timeline:

```text
22:00  Host discovery
22:03  Service enumeration
22:08  Vulnerable service identified
22:12  Initial access
22:15  Local enumeration
22:22  Privilege escalation
22:30  Lateral movement
22:40  Evidence collected
22:45  Cleanup
```

Then map every step to a defensive detection.

## Final exercise: attack and defend

Run the range twice.

### Run A — Red team

Try to reach the final server.

### Run B — Blue team

Use your logs and packet captures to answer:

- Where was the first suspicious event?
- Which source IP did it come from?
- Which account was used?
- Which process ran?
- What network connection followed?
- What control would have stopped it earlier?

Then fix the highest-value weakness and run the red-team path again.

## What "finished" looks like

You are not finished because you can run Metasploit.

You are getting good when you can look at:

```text
Nmap output
PCAP
SSH logs
DNS logs
HTTP logs
process list
firewall logs
```

and reconstruct what happened.

That is the bridge between pentesting, red teaming and defensive security.
