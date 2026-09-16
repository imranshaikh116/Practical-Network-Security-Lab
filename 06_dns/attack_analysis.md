# 06 — DNS: Name Resolution Abuse, Cache Poisoning, and Trust Breakdown

## Concept first: DNS is both lookup and trust

DNS translates names to addresses, but it also creates trust relationships between clients and resolvers. If a resolver accepts an attacker-controlled answer, the client may be redirected to the wrong IP even when the service name looks legitimate.

### Offensive angle

The attacker studies the resolver path, cache behavior, TTLs, and query flow. In a lab, a private zone is safer than attacking public domains because it lets you see exactly how incorrect responses are cached, propagated, and detected.

### Defensive angle

Defenders enforce trusted resolvers, monitor for unexpected DNS providers, validate TTL and record changes, and add DNSSEC where possible. The security objective is not only fast resolution but authenticated and expected answers.

### Commands explained

- `dig A example.com` and `dig +noall +answer`: inspect ordinary DNS resolution behavior.
- `resolvectl status` and `cat /etc/resolv.conf`: reveal which recursive resolver the host is using.
- `dig @192.168.56.30 web.lab.test`: query a controlled lab DNS zone.
- `dig +dnssec example.com`: explore how DNSSEC authenticates records.
- `tcpdump port 53`: capture request/response packets and verify what the client actually received.

The key concept is that DNS compromise is a trust problem, not just a query problem.

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

## Understand the normal transaction

Run:

```bash
dig A example.com
dig +noall +answer example.com
```

Look at:

- query name
- query type
- resolver
- answer
- TTL

Find your configured resolver:

```bash
resolvectl status
cat /etc/resolv.conf
```

## Build a private DNS zone

Do not experiment by spoofing real domains.

Create a zone such as:

```text
lab.test
```

with:

```text
web.lab.test
api.lab.test
```

Run it on your dedicated DNS VM.

From the client:

```bash
dig @192.168.56.30 web.lab.test
```

Capture it:

```bash
sudo tcpdump -i any -nn -w ~/lab/06_dns.pcap port 53
```

## Deliberately wrong answer

Change the private zone so:

```text
web.lab.test → 192.168.56.99
```

where `.99` is another disposable VM.

Query again:

```bash
dig @192.168.56.30 web.lab.test
```

This is the safest way to understand DNS manipulation: you control the authoritative data and the client.

## Cache behavior

Observe TTL:

```bash
dig @192.168.56.30 web.lab.test
```

Change the record and query again.

If a recursive cache sits between the client and authoritative server, the old answer may remain until the TTL expires.

This is why DNS security is not just "the answer was wrong." You need to understand where the answer came from and how long it can be cached.

## Study poisoning conceptually

DNS cache poisoning tries to get a resolver to cache an attacker-controlled response.

Modern resolvers make this harder with:

- randomized transaction IDs
- randomized source ports
- DNSSEC validation
- hardened resolver behavior

You can reproduce the *idea* safely with your private lab zone rather than trying to poison public resolvers.

## DNS reconnaissance

Useful commands:

```bash
dig A lab.test
dig NS lab.test
dig MX lab.test
dig TXT lab.test
```

Against your own DNS server:

```bash
dig @192.168.56.30 ANY lab.test
```

Be aware that modern authoritative servers may restrict ANY responses.

## Defensive monitoring

Look for:

- clients suddenly using an unexpected resolver
- multiple answers for the same name
- unusual NXDOMAIN volume
- very short TTLs
- DNS requests to suspicious infrastructure
- DNS traffic outside approved resolvers

## DNSSEC study

Try:

```bash
dig +dnssec example.com
```

Then read the returned DNSSEC records and learn the chain of trust:

```text
Root
 ↓
TLD
 ↓
Authoritative zone
 ↓
Signed record
```

The key lesson is authentication of DNS data, not secrecy of DNS queries.

## Final exercise

Build a private DNS attack-and-defense story:

1. Normal answer.
2. Modified private answer.
3. Packet capture.
4. Client behavior.
5. Detection.
6. Correct the DNS configuration.
7. Retest.
