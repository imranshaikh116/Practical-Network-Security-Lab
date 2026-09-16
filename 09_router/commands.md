# 09 Command Notebook — Router Security and Management Plane

A router is usually a high-value target because it controls the data path behind it. The offensive angle is to discover the management plane, identify exposed services, and test whether the admin interface is reachable or misconfigured. The defensive angle is to lock down management access and ensure the router exposes only required services.

## 1) Find the router and normal traffic path

```bash
ip route
```

### Offensive purpose
- Shows the default gateway and the path the host uses to leave the local network.

### Defensive purpose
- Confirms the correct gateway is configured and there is no unexpected route manipulation.

---

## 2) Scan the router for exposed services

```bash
nmap -p- 192.168.56.1
nmap -sV 192.168.56.1
```

### Offensive purpose
- Reveals which ports are open on the router.
- `-sV` identifies the service versions and likely management interfaces.

### Defensive purpose
- Helps the blue team answer: what management ports are exposed, and which ones should not be reachable?

---

## 3) Inspect the web management interface

```bash
curl -I http://192.168.56.1/
curl -v http://192.168.56.1/
```

### Offensive purpose
- Checks whether the router exposes an HTTP admin UI.
- `-v` shows response headers, redirects, status codes, and negotiation behavior.

### Defensive purpose
- If the router exposes a management interface on the wrong segment, that is a serious issue.
- Defenders can compare the expected admin path against what is actually reachable.

---

## 4) Inspect SSH access and admin exposure

```bash
ssh -v admin@192.168.56.1
```

### Offensive purpose
- Tests whether SSH is enabled and whether there are reachable login prompts.
- `-v` reveals negotiation and protocol details.

### Defensive purpose
- Blue teams can determine whether SSH is exposed to the wrong network or whether default credentials or weak authentication policies are present.

---

## 5) Validate server-side exposure

```bash
ss -lntup
ip addr
ip route
```

### Offensive purpose
- Shows which ports are bound and whether the device is exposing admin services beyond what a user should expect.

### Defensive purpose
- This is how you verify that a router no longer exposes unnecessary services after hardening.

---

## Defensive hardening checklist

- Restrict management to the proper VLAN or admin segment
- Disable unused services
- Use strong admin credentials and MFA if available
- Update router firmware
- Disable WAN management if not needed
- Log admin access and configuration changes

### Key lesson
- The real target is not the internet; it is the management plane that controls the network.
