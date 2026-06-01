# Splunk SIEM Home Lab — SSH Brute Force Detection

> Complete setup guide covering log forwarding, attack simulation, SPL queries, and dashboard creation.

---

## Table of Contents

- [Universal Forwarder Setup](#1-universal-forwarder-setup)
- [Receiver Configuration](#2-receiver-configuration)
- [Testing Connectivity](#3-testing-connectivity)
- [Attack Simulation](#4-attack-simulation)
- [Dashboard Panels](#5-dashboard-panels)

---

## 1. Universal Forwarder Setup

### Download

```bash
wget -O splunkforwarder.tgz "https://download.splunk.com/products/universalforwarder/releases/10.2.3/linux/splunkforwarder-10.2.3-4d61cf8a5c0c-linux-amd64.tgz"
```

### Extract and Start

```bash
sudo su
tar -xvzf splunkforwarder.tgz -C /opt
cd /opt/splunkforwarder/bin
./splunk start --accept-license
```

### Point Forwarder to Receiver

```bash
./splunk add forward-server 192.168.0.102:9997
```

| Parameter | Meaning |
|---|---|
| `192.168.0.102` | IP of the Splunk Enterprise machine |
| `9997` | Default Splunk receiving port |

### Configure Log Sources

```bash
# System events
./splunk add monitor /var/log/syslog -index main -sourcetype syslog

# Authentication events (SSH logins, failures, sudo)
./splunk add monitor /var/log/auth.log -index main -sourcetype authlog
```

### Restart and Verify

```bash
./splunk restart
./splunk list forward-server
```

---

## 2. Receiver Configuration

### Enable Receiving Port in Splunk Web

```
Settings → Forwarding and Receiving → Receive Data
→ Configure Receiving → New Receiving Port → 9997
```

### Open Firewall (Windows Host)

```
Windows Defender Firewall → Advanced Settings
→ Inbound Rules → New Rule → TCP → Port 9997
```

---

## 3. Testing Connectivity

### Verify Network Path from VM

```bash
nc -zv 192.168.0.102 9997
```

**Expected output:**
```
Connection to 192.168.0.102 9997 port [tcp/*] succeeded!
```

This confirms the network path is open, the firewall allows traffic, and Splunk is listening.

### Generate a Test Log Entry

```bash
logger -p user.crit -t SECURITY_ALERT "Unauthorized root access attempt detected from malicious external IP 198.51.100.42. Action: Blocked."
```

| Flag | Meaning |
|---|---|
| `logger` | Writes directly into the Linux logging system |
| `-p user.crit` | Sets severity to critical |
| `-t SECURITY_ALERT` | Adds a custom tag to the event |

If forwarding is working, this event appears in Splunk within seconds.

---

## 4. Attack Simulation

Simulates a real SSH brute-force attack (MITRE ATT&CK **T1110.001**) using Nmap's `ssh-brute` NSE script.

```bash
nmap -p 22 --script ssh-brute \
  --script-args "userdb=C:\Users\Durvesh\wekafiles\user.txt,passdb=C:\Users\Durvesh\wekafiles\top-20-common-SSH-passwords.txt" \
  192.168.0.103
```

| Argument | Purpose |
|---|---|
| `-p 22` | Target SSH port |
| `--script ssh-brute` | Runs Nmap's built-in SSH brute-force script |
| `userdb` | File containing username(s) to try |
| `passdb` | Wordlist of passwords to try |
| `192.168.0.103` | Target Linux VM |

**What happens:**
The VM generates a burst of failed authentication entries in `/var/log/auth.log`. The Universal Forwarder ships them to Splunk, where the dashboard panels light up with the attack data.

---

## 5. Dashboard Panels

### Panel 1

**Visualization:** Line chart

```spl
index=main sourcetype=linux_secure "Failed password"
| timechart span=1m count AS "Failed Logins"
```

**How it works:**

| SPL component | What it does |
|---|---|
| `index=main sourcetype=linux_secure` | Targets Linux auth logs from `/var/log/auth.log` |
| `"Failed password"` | Filters to events containing that exact phrase |
| `timechart span=1m` | Groups events into 1-minute buckets on the X-axis |
| `count AS "Failed Logins"` | Counts events per bucket, renames the column |

**Example output:**

| Time | Failed Logins |
|---|---|
| 22:00 | 2 |
| 22:01 | 14 ← attack spike |
| 22:02 | 1 |

---

### Panel 2

**Visualization:** Bar chart

```spl
index=main sourcetype=linux_secure "Failed password"
| rex field=_raw "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count AS attempts BY src_ip
| sort -attempts
| head 10
```

**How it works:**

| SPL component | What it does |
|---|---|
| `rex field=_raw "from (?<src_ip>...)"` | Extracts attacker IP from raw log text |
| `stats count AS attempts BY src_ip` | Counts failures grouped by IP address |
| `sort -attempts` | Sorts descending — highest count first |
| `head 10` | Shows only the top 10 IPs |

**Regex breakdown:**

```
from (?<src_ip>\d+\.\d+\.\d+\.\d+)
│     │         └── matches an IPv4 address
│     └── stores match in field named src_ip
└── finds the word "from" in the log line
```

**Example log line matched:**
```
Failed password for root from 192.168.1.50 port 22 ssh2
                              └─────────────┘
                              extracted as src_ip
```

---

### Panel 3

**Visualization:** Statistics table

```spl
index=main sourcetype=linux_secure
| rex field=_raw "(?<status>Failed|Accepted) password.*from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(status="Failed")) AS failures,
        count(eval(status="Accepted")) AS successes
  BY src_ip
| where failures > 3 AND successes > 0
| eval risk="HIGH"
| table src_ip failures successes risk
```

**How it works:**

| SPL component | What it does |
|---|---|
| `rex` extracts `status` | Captures either `Failed` or `Accepted` from each log line |
| `rex` extracts `src_ip` | Captures the source IP address |
| `stats count(eval(...))` | Counts failures and successes separately per IP |
| `where failures > 3 AND successes > 0` | The core detection logic — see below |
| `eval risk="HIGH"` | Tags every matching row as high risk |
| `table` | Produces a clean final report |

**Detection logic explained:**

```
failures > 3  →  attacker tried multiple passwords
successes > 0 →  one of them worked
```

An IP meeting both conditions likely completed a successful brute-force.

| src_ip | failures | successes | Kept? |
|---|---|---|---|
| 192.168.1.50 | 8 | 1 | ✅ HIGH risk |
| 192.168.1.60 | 12 | 0 | ❌ No success |
| 192.168.1.70 | 1 | 2 | ❌ Too few failures |

**Example output:**

| src_ip | failures | successes | risk |
|---|---|---|---|
| 192.168.1.50 | 8 | 1 | HIGH |

---
