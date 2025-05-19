![image](https://github.com/user-attachments/assets/fa12d83a-4d01-429a-9cda-657b3ffd5e82)# Detection Use Case: Brute Force Attack Detection

## Scenario Description
An attacker attempts multiple failed SSH login attempts on a Linux machine (`auth.log`), followed by a successful login from the same IP. This behavior may indicate a successful brute-force attack.

## Objective
This detection should identify excessive failed login attempts from the same IP followed by a successful login, which can indicate brute-force behavior and credential compromise.

## Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux (`/var/log/auth.log`)
- **Lab Setup**: 
  - Linux VM (Kali) running Splunk Universal Forwarder
  - Windows host running Splunk Enterprise
  - Logs monitored: `/var/log/auth.log`
  - Data forwarded to Splunk Enterprise over TCP port `9997`

---

## Event ID / Data Source Mapping

### 🔐 SSH Authentication Event Log (Extracted from Splunk)

| `_time`                       | `status` | `username` | `fail_user` | `success_user` | `src_ip`     | `host` | `index`     | `source`              | `sourcetype` | `splunk_server` | `consecutive_failures` | `last_fail_time_epoch` | `success_time_epoch` |
|------------------------------|----------|------------|-------------|----------------|--------------|--------|-------------|------------------------|--------------|------------------|------------------------|------------------------|----------------------|
| 2025-05-15T18:28:40.541+0530 | failed   | kali       | kali        |                | 192.168.1.7  | kali   | linux_logs | /var/log/auth.log      | auth         | KANHA           | 10                     | 1747313920             | 1747313921           |
| 2025-05-15T18:28:40.641+0530 | failed   | kali       | kali        |                | 192.168.1.7  | kali   | linux_logs | /var/log/auth.log      | auth         | KANHA           | 10                     | 1747313921             | 1747313921           |
| 2025-05-15T18:28:40.657+0530 | failed   | kali       | kali        |                | 192.168.1.7  | kali   | linux_logs | /var/log/auth.log      | auth         | KANHA           | 10                     | 1747313921             | 1747313921           |
| 2025-05-15T18:28:40.807+0530 | success  | kali       |             | kali           | 192.168.1.7  | kali   | linux_logs | /var/log/auth.log      | auth         | KANHA           | 10                     | 1747313921             | 1747313921           |


## Detection Logic / Query (Splunk SPL)


