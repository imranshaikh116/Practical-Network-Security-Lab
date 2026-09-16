# 02 — Networking: Packet Analysis, Traffic Flow, and Adversary Recon

## Concept first: the network is a layered system

This scenario is about understanding how traffic moves across layers, from physical signaling to application behavior. Network attacks are often not "magic"; they are normal protocol behavior being abused because a system trusted the wrong source, the wrong MAC, or the wrong DNS answer.

### Offensive angle

An attacker follows the packet path to see where trust breaks. For example, ARP poisoning turns a local network into a forwarding problem. A TCP handshake reveals whether the remote service is live. DNS queries tell you which name resolution path a client is using.

### Defensive angle

A defender must be able to recognize benign traffic from malicious manipulation. That means checking routes, ARP tables, DNS resolvers, socket states, and packet captures. The defense is not only firewalling; it is understanding the protocol and knowing when a behavior is abnormal.

### Commands explained

- `ip route` and `ip neigh`: show the routing table and Layer 2 neighbor mappings.
- `ss -ant` and `ss -uan`: expose TCP and UDP socket states and listeners.
- `curl -v`: show the exact HTTP request and response flow, including headers and handshake behavior.
- `tcpdump`: reveals the packet-level proof behind a network event.
- `dig`: lets you inspect DNS request and response data, especially cache and resolution behavior.

The key offensive/defensive question is always: who is trusted, at what layer, and what evidence proves it?

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

## The layers you need in your head

When something goes wrong, move down the stack instead of guessing.

```text
Application: HTTP, DNS, SSH
Transport:   TCP, UDP
Network:     IPv4, IPv6, ICMP
Link:        Ethernet, ARP
Physical:    VM virtual NIC / virtual switch
```

For example, an HTTP request failing could be an application problem, a closed TCP port, a route problem, or an ARP problem. The command you choose should tell you which layer is broken.

## Interface and route inspection

```bash
ip -br addr
ip link
ip route
ip neigh
```

Look at the route selected for a target:

```bash
ip route get 192.168.56.20
```

Check sockets:

```bash
ss -lntup
ss -ant
ss -uan
```

## TCP behavior

Start a temporary server on your target:

```bash
python3 -m http.server 8080 --bind 192.168.56.20
```

From Kali:

```bash
curl -v http://192.168.56.20:8080/
```

Capture it:

```bash
sudo tcpdump -i any -nn -w ~/lab/02_http.pcap host 192.168.56.20 and port 8080
```

Look for the TCP three-way handshake:

```text
SYN → 
     ← SYN/ACK
ACK →
```

Then look at the HTTP request.

## UDP is different

Run a UDP listener in your own lab:

```bash
nc -u -l 9000
```

From another VM:

```bash
echo "hello" | nc -u 192.168.56.20 9000
```

Capture:

```bash
sudo tcpdump -i any -nn udp port 9000
```

There is no TCP handshake because UDP does not establish a connection in the same way.

## ARP

Check the neighbor table:

```bash
ip neigh
```

Generate local traffic and watch ARP:

```bash
sudo tcpdump -i any -nn arp
ping -c 2 192.168.56.20
```

Ask yourself:

- Which machine owns the IP?
- Which MAC address is being associated with it?
- What happens when the mapping changes?

Those questions lead directly into MITM and ARP poisoning.

## DNS

```bash
dig example.com
dig A example.com
dig MX example.com
dig NS example.com
dig +trace example.com
```

Use a private DNS zone later in the course so you can deliberately manipulate answers without touching real domains.

## Nmap as a network-learning tool

Start small:

```bash
nmap -sn 192.168.56.0/24
nmap -p 22,80,443 <TARGET>
nmap -sV <TARGET>
nmap -p- <TARGET>
```

Compare the results. A full TCP port scan answers a different question from a version scan.

## Packet-analysis exercise

Capture:

```bash
sudo tcpdump -i any -nn -w ~/lab/02_dns.pcap port 53
```

Then:

```bash
dig example.com
```

Read:

```bash
tcpdump -nn -r ~/lab/02_dns.pcap
```

Open the PCAP in Wireshark and identify:

- source IP
- destination IP
- source port
- destination port
- protocol
- DNS query
- DNS response
- TTL

If you can explain a packet capture without looking at a cheat sheet, your networking foundation is becoming solid.
