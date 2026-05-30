# Splunk SIEM Home Lab — SSH Brute Force Detection

## Overview
Built a local SIEM pipeline to monitor a Linux VM, simulate a 
real SSH brute-force attack, detect it with a correlation rule, 
and visualize the results on a security dashboard.

---

## Architecture

Host Machine (192.168.0.102) — Windows
└── Splunk Enterprise (receives logs, runs detections)
└── Nmap (attack simulation tool)

VM (192.168.0.103) — Linux (VMware)
└── Splunk Universal Forwarder (ships logs to host)
└── SSH enabled (attack target)

Data flow: VM logs → UF → TCP 9997 → Splunk Enterprise

---

## What Was Built

### 1. Log Pipeline
- Installed Splunk Universal Forwarder on Linux VM
- Configured forwarder to monitor:
  - /var/log/auth.log  (SSH login events)
  - /var/log/syslog    (system events)
- Opened TCP 9997 on Windows firewall
- Verified real-time log delivery to Splunk Enterprise

### 2. Attack Simulation (MITRE ATT&CK T1110.001)
- Used Nmap ssh-brute script from host machine targeting VM SSH
- Wordlist: top 20 common SSH passwords + actual password appended
- Fixed single username via userdb file
- Generated realistic failed login burst in auth.log

Command used:
nmap -p 22 --script ssh-brute \
  --script-args "userdb=C:\path\user.txt,passdb=C:\path\passwords.txt" \
  192.168.0.103

### 3. Detection Rule (Correlation Alert)
- Written in SPL using streamstats sliding window
- Fires when 5+ failed logins from same IP within 60 seconds
- Scheduled every 5 minutes via Cron: */5 * * * *
- Trigger action: Add to Triggered Alerts
- File: detections/ssh_brute_force.spl

### 4. Security Dashboard (3 Panels)
Panel 1 — Failed logins over time (line chart)
Panel 2 — Top attacking IPs (bar chart)  
Panel 3 — Brute force success correlation table
           (IPs with failures AND successful login = HIGH risk)

Plus 3 single-value KPI tiles:
- Total failed logins
- Unique attacking IPs  
- Compromised accounts detected

---

## Tools Used
- Splunk Enterprise 9.x
- Splunk Universal Forwarder
- Nmap 7.93 (ssh-brute NSE script)
- VMware Workstation
- Linux (Ubuntu/Debian)
- Windows 11 (host)

---

## Key Skills Demonstrated
- SIEM deployment and configuration
- Log forwarding and pipeline setup
- Threat simulation (T1110.001 SSH Brute Force)
- SPL query writing and correlation logic
- Security dashboard design
- Alert engineering

---

## Screenshots
- dashboard_overview.png
- alert_triggered.png
- nmap_attack_output.png
- splunk_events_realtime.png
