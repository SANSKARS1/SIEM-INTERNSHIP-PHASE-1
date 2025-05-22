# Detection Use Case: Malicious User Creation on Linux

## 📝 Scenario Description
An attacker gains access to a Linux system and adds a new user using commands like `useradd`, `adduser`, or modifies existing accounts using `passwd -d`, `passwd -l`, or `usermod`. This behavior can be part of persistence tactics.

## 🎯 Objective
Detect potentially unauthorized or malicious account creation or modification on Linux systems by monitoring command-line activities.

## 🛠️ Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux Syslog (`/var/log/auth.log`)
- **Lab Setup**:
  - Kali Linux VM with Splunk Universal Forwarder
  - Windows host running Splunk Enterprise
  - Logs forwarded from `/var/log/auth.log` to Splunk over TCP port `9997`

---

## 📊 Data Source Mapping

### 🔍 Authlog (Auth Events)

| Field     | Example Value           | Description                                |
|----------|--------------------------|--------------------------------------------|
| `_time`  | `2025-05-20T21:50:40.123` | Timestamp of the event                     |
| `host`   | `kali`                   | Hostname where the command was executed    |
| `user`   | `root`                   | User that executed the command             |
| `new_user` | `suspicioususer`      | Username being added or modified           |
| `_raw`   | `useradd suspicioususer` | Raw log entry showing the exact command    |

---

## 🛡️ Detection Logic: User Addition or Modification

Detect user creation or modification commands by parsing logs for specific binaries and arguments.

### 🔎 SPL Query

```spl
index="linux_logs" sourcetype="auth" 
("useradd" OR "adduser" OR "passwd -l" OR "passwd -d" OR "usermod")
| rex "useradd\s+(?<new_user>\w+)"
| table _time host user new_user _raw
| sort -_time
```


