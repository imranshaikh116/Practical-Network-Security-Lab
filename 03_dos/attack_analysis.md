# 03 — Denial of Service: Resource Exhaustion and Service Degradation Analysis

## Concept first: DoS is about finite resources

Denial of service is not only a flood. It is any condition where demand exceeds resource capacity, such as CPU, memory, network bandwidth, file descriptors, database connections, or application workers. Attackers exploit bottlenecks; defenders add rate limits, timeouts, and protections that reduce sensitivity to spikes.

### Offensive angle

The offensive technique is to identify the bottleneck and push it until it fails. This can be at the network layer, like SYN saturation, or at the application layer, like slow requests that exhaust worker threads. The important skill is to measure the effect and explain which resource is the limiting factor.

### Defensive angle

The defender asks: what resource is being starved, how are we measuring normal traffic, and how do we absorb bursts without breaking service? Rate limiting, reverse proxies, connection timeouts, and load balancing are all responses to the same idea: avoid letting one client exhaust shared resources.

### Commands explained

- `uptime`, `free -h`, `df -h`, `ss -s`: establish the target's resource baseline.
- `ab` (ApacheBench): generate controlled HTTP load for benchmarking.
- `ss -ant | awk ...`: view connection states to understand exhaustion behavior.
- `tcpdump`: capture attempted flows so you can explain the resource problem at the packet level.
- `journalctl`: checks server-side evidence of overload or crashes.

The real lesson is not "the attack worked." The real lesson is which resource failed and what control prevented it.

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

## The useful way to study DoS

Do not start with "what tool can flood a target?"

Start with the resource:

```text
CPU?
RAM?
File descriptors?
TCP connection table?
Application workers?
Disk?
Bandwidth?
Database connections?
```

A DoS happens when demand exceeds the resource available to the service.

## Baseline

On the target:

```bash
uptime
free -h
df -h
ss -s
top
```

For an HTTP service:

```bash
curl -s -o /dev/null -w '%{http_code} %{time_total}\n' http://<TARGET>/
```

Repeat it a few times and record normal latency.

## Controlled HTTP load

Install ApacheBench on your lab attacker if necessary.

Start very small:

```bash
ab -n 50 -c 2 http://<TARGET>/
```

Then, only if the target remains stable:

```bash
ab -n 200 -c 5 http://<TARGET>/
```

This is deliberately small. You are measuring behavior, not trying to knock a machine offline.

Watch the target at the same time:

```bash
top
ss -s
journalctl --since "2 minutes ago"
```

## Study connection exhaustion

Look at TCP states:

```bash
ss -ant | awk 'NR>1 {print $1}' | sort | uniq -c | sort -nr
```

This gives you a rough picture of how many sockets are in states such as ESTAB, TIME-WAIT and SYN-RECV.

Capture:

```bash
sudo tcpdump -i any -nn -w ~/lab/03_load.pcap host <TARGET>
```

Compare the normal capture and the load-test capture.

## A safe SYN study

You can study SYN behavior without generating a flood. Capture ordinary connection attempts:

```bash
sudo tcpdump -i any -nn 'tcp[tcpflags] & tcp-syn != 0'
```

Open a connection to a known lab service and observe the SYN/SYN-ACK/ACK sequence.

The defensive lesson is more important than the generator: SYN cookies, backlog tuning, rate limits, reverse proxies and upstream protection exist because servers have finite connection resources.

## Application-layer DoS

Create a deliberately slow endpoint in a local test application and see how worker processes behave.

Measure:

```bash
ps aux --sort=-%cpu | head
ps aux --sort=-%mem | head
ss -s
```

## Detection

A basic detector might compare requests per second against a baseline.

For web logs:

```bash
awk '{print $4}' /var/log/nginx/access.log | cut -d: -f1 | sort | uniq -c
```

For a simple top-client view, adapt the fields to your log format:

```bash
awk '{print $1}' /var/log/nginx/access.log | sort | uniq -c | sort -nr | head
```

## Defense lab

Apply a rate limit in the reverse proxy or application. Run the exact same small load again.

Record:

```text
Before:
Requests:
Average latency:
Errors:
CPU:
Connections:

After:
Requests:
Average latency:
Errors:
CPU:
Connections:
```

That before/after comparison is the real exercise.

## Red-team question

If the service survives the load, what did you actually learn?

You learned which resource is protected, where the bottleneck moved, and what the defender has already controlled. That is much more useful than simply saying "the attack failed."
