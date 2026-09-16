# 03 Command Notebook — DoS and Resource Exhaustion

This module is about resource exhaustion, not just traffic floods. The attacker wants to identify the bottleneck and push it until the service degrades or fails. The defender wants to know which resource is under pressure and which control is absorbing the load.

## 1) Establish machine baseline

```bash
uptime
free -h
df -h
ss -s
top
```

### Offensive purpose
- `uptime`: tells you whether the system is healthy or already under strain.
- `free -h`: reveals RAM usage to detect memory pressure.
- `df -h`: shows disk usage and whether storage exhaustion is a factor.
- `ss -s`: summarizes TCP socket states and connection pressure.
- `top`: gives a real-time view of CPU, memory, and process activity.

### Defensive purpose
- These commands create a baseline of normal system behavior before generating load.
- If the target starts failing under moderate traffic, you can identify whether the bottleneck is CPU, RAM, disk, or sockets.

---

## 2) Controlled HTTP load generation

```bash
ab -n 50 -c 2 http://<TARGET>/
ab -n 200 -c 5 http://<TARGET>/
```

### Offensive purpose
- `ab` (ApacheBench) is a simple way to send controlled requests to a web service.
- `-n` sets the total number of requests.
- `-c` sets the concurrency level.

### Defensive purpose
- This is useful to show how a web service behaves under load.
- A defender can use this to test rate limiting, reverse proxy tuning, worker limits, or CDN protection.

### Lab rule
- Keep requests modest and the network isolated.
- You are measuring behavior, not trying to crash a machine.

---

## 3) Detect connection exhaustion

```bash
ss -ant | awk 'NR>1 {print $1}' | sort | uniq -c | sort -nr
```

### Offensive purpose
- Summarizes TCP socket states such as `ESTAB`, `TIME_WAIT`, or `SYN_RECV`.
- This helps identify whether the service is exhausting connection capacity or mismanaging state.

### Defensive purpose
- Blue teams use this to detect connection storms and abnormal socket behavior.
- A surge in connection count often reveals a DoS, a slowloris pattern, or a workload that is saturating server-side resources.

---

## 4) SYN observation without full flood

```bash
sudo tcpdump -i any -nn 'tcp[tcpflags] & tcp-syn != 0'
```

### Offensive purpose
- Show the raw SYN traffic that indicates connection attempts.
- This helps explain how a TCP service is being hit before you escalate to load generation.

### Defensive purpose
- SYN monitoring is central to understanding SYN flood behavior and whether the host is absorbing connection requests poorly.
- The defender can correlate these packets with system socket state and service logs.

---

## 5) Observe logs while the target is under load

```bash
journalctl --since "5 minutes ago"
```

### Offensive purpose
- Look for warnings, errors, process restarts, or failures during a stress test.

### Defensive purpose
- Logs help correlate service degradation with abnormal behavior and reveal the point where the system started to fail.

---

## Defensive controls to test

- Rate limiting at the reverse proxy or application layer
- Connection timeouts and backlog tuning
- Load balancing or CDN protection
- `ab`-style load tests against the same service before and after the change

### Good comparison
- Before: requests, latency, error count, CPU, sockets
- After: same workload, same metrics

This turns a vague “attack failed” into an evidence-based explanation of which control actually helped.
