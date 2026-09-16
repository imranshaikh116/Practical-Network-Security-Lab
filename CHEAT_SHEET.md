# Offensive vs Defensive Command Cheat Sheet

This cheat sheet is meant to help students understand the same tool from both sides:

- Offensive use: how an attacker uses the command to validate exposure or abuse a trust boundary
- Defensive use: how a defender uses the same command to detect, measure, or block the behavior
- Evidence value: what the output proves and what should be captured in a report

## 1) Reconnaissance and baseline

| Command | Offensive purpose | Defensive purpose | Evidence to capture |
|---|---|---|---|
| `whoami` | Confirms current privilege and likely access level | Confirms the account context on a host | Screenshot or command log |
| `id` | Shows user and group context | Validates whether account privilege is expected | Output showing uid/gid |
| `hostname` | Identifies the target host identity | Confirms host naming and asset inventory | Host name and system record |
| `uname -a` | Reveals OS and kernel details for targeting | Validates expected OS baseline | Output showing OS version |
| `ip addr` | Shows interface and IP mapping | Establishes host baseline and network inventory | Interface and address output |
| `ip route` | Reveals the default gateway and path | Validates expected routing and trust boundaries | Route table output |
| `ss -lntup` | Lists open services and listeners | Detects unexpected services | Port and process mapping |
| `ps aux` | Finds running processes and potential privilege targets | Detects unusual or malicious processes | Process table output |
| `nmap -sn 192.168.56.0/24` | Discovers live hosts | Detects perimeter or internal reconnaissance | Scan output and source IP |
| `nmap -sV <target>` | Profiles service versions and banners | Validates exposure and outdated software | Service/version output |

## 2) Traffic and packet analysis

| Command | Offensive purpose | Defensive purpose | Evidence to capture |
|---|---|---|---|
| `tcpdump -i any -nn` | Captures live traffic for analysis | Detects suspicious traffic or unexpected protocol use | Packet excerpts or PCAP |
| `tcpdump -nn port 53` | Observes DNS behavior | Detects suspicious resolution or exfiltration patterns | DNS transaction samples |
| `tcpdump -nn arp` | Observes local trust and neighbor mapping | Detects ARP poisoning or spoofing attempts | ARP packets and timing |
| `tcpdump -A tcp port 80` | Sees plaintext HTTP requests/responses | Detects cleartext traffic and unsafe protocols | HTTP data samples |
| `dig example.com` | Tests DNS resolution and trust path | Verifies expected resolver behavior | Query and answer output |
| `curl -I http://host` | Confirms service reachability and headers | Verifies a service is operating as expected | Response headers and status code |
| `curl -v http://host` | Explores request/response behavior | Detects unexpected redirects or app behavior | Full HTTP transaction |

## 3) Network trust abuse

| Command | Offensive purpose | Defensive purpose | Evidence to capture |
|---|---|---|---|
| `ip neigh` | Maps local trust between IP and MAC | Detects unexpected neighbor changes | ARP neighbor table |
| `arpspoof -i eth0 -t <client> <gateway>` | Poison a victim’s ARP cache | Detects malicious ARP activity and relay behavior | ARP poisoning sequence |
| `sysctl -w net.ipv4.ip_forward=1` | Enables traffic forwarding for MITM | Detects unexpected relay hosts | Forwarding state and PCAP |
| `dhclient` | Requests a lease from a rogue DHCP source | Validates expected DHCP behavior on the segment | Lease and route changes |
| `ip route` | Shows the active path used by the client | Validates unexpected route changes | Before/after route table |

## 4) Service and privilege review

| Command | Offensive purpose | Defensive purpose | Evidence to capture |
|---|---|---|---|
| `sudo -l` | Finds possible privilege escalation | Detects dangerous privilege exposure | `sudo` policy output |
| `find / -perm -4000` | Identifies privileged binaries | Detects risky SUID/privileged binaries | File and permission listing |
| `systemctl --type=service --state=running` | Finds active services and attack surface | Confirms intended service set | Active service list |
| `journalctl --since "1 hour ago"` | Reads historical behavior and mistakes | Detects suspicious events and abuse history | Relevant log excerpts |
| `grep -i "failed" /var/log/auth.log` | Finds weak or compromised credential paths | Detects failed authentication patterns | Auth log lines |

## 5) Defenses and hardening

| Command | Offensive purpose | Defensive purpose | Evidence to capture |
|---|---|---|---|
| `ufw status` | Confirms whether a host is protected at the edge | Reviews firewall policy and exposure | Before/after firewall status |
| `nft list ruleset` | Shows the live filter policy | Validates intent and enforcement | Rule set output |
| `systemctl disable --now <service>` | Removes a target service from the environment | Reduces attack surface and exposure | Service status before/after |
| `ss -lntup` | Re-checks open ports after a change | Validates the reduced attack surface | Port inventory after hardening |
| `nmap -sV <target>` | Re-tests the remaining exposure | Confirms the fix actually works | Post-fix scan output |

## 6) Decision rule: when to stop

Do not keep escalating just because a tool works. Stop when:

- the trust failure is clearly proven
- the impact is explained
- the defense or detection path is understood
- enough evidence exists for the report

This is the difference between a genuine red-team workflow and noisy activity.

## 7) What the course is really testing

The goal is not command memorization. The goal is to answer:

- what is exposed
- what is trusted
- what is vulnerable
- what evidence proves it
- what a defender would see
- what control would stop it
- when to document and stop
