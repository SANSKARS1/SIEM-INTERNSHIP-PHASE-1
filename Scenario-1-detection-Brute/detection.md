# Detection Use Case: Brute Force Attack Detection

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

##  Data Source Mapping

### 🔐 SSH Authentication Event Log (Extracted from Splunk)

| `_time`                       | `status` | `username` | `fail_user` | `success_user` | `src_ip`     | `host` | `index`     | `source`              | `sourcetype` | `splunk_server` | `consecutive_failures` | `last_fail_time_epoch` | `success_time_epoch` |
|------------------------------|----------|------------|-------------|----------------|--------------|--------|-------------|------------------------|--------------|------------------|------------------------|------------------------|----------------------|
| 2025-05-15T18:28:40.541+0530 | failed   | kali       | kali        |                | 192.168.1.7  | kali   | linux_logs | /var/log/auth.log      | auth         | KANHA           | 10                     | 1747313920             | 1747313921           |
| 2025-05-15T18:28:40.641+0530 | failed   | kali       | kali        |                | 192.168.1.7  | kali   | linux_logs | /var/log/auth.log      | auth         | KANHA           | 10                     | 1747313921             | 1747313921           |
| 2025-05-15T18:28:40.657+0530 | failed   | kali       | kali        |                | 192.168.1.7  | kali   | linux_logs | /var/log/auth.log      | auth         | KANHA           | 10                     | 1747313921             | 1747313921           |
| 2025-05-15T18:28:40.807+0530 | success  | kali       |             | kali           | 192.168.1.7  | kali   | linux_logs | /var/log/auth.log      | auth         | KANHA           | 10                     | 1747313921             | 1747313921           |

![5](https://github.com/user-attachments/assets/6fa1a041-4a2c-4fe8-8693-2f61b066a3a8)

### 🛡️ Detection Logic: SSH Brute-Force Followed by Success

This SPL (Search Processing Language) query detects cases where a brute-force attack (≥10 failed SSH login attempts) is followed by a successful login **within 2 minutes** from the same `src_ip` and targeting the same `username`.

#### 🔍 SPL Query Used:

```spl
index="linux_logs" sourcetype=auth ("Failed password" OR "Accepted password")
| rex "from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval status=if(searchmatch("Failed password"), "failed", "success")
| rex "Failed password for (?<fail_user>\w+)"
| rex "Accepted password for (?<success_user>\w+)"
| eval username=coalesce(fail_user, success_user)
| sort 0 _time
| streamstats current=f window=10 count(eval(status="failed")) as consecutive_failures by src_ip, username
| streamstats current=f last(_time) as last_fail_time_raw by src_ip, username
| where consecutive_failures >= 10 
| eval success_time_epoch=round(_time)
| eval last_fail_time_epoch=round(last_fail_time_raw)
| eval time_diff = success_time_epoch - last_fail_time_epoch
| where time_diff <= 120
| stats min(last_fail_time_epoch) as last_fail_time max(success_time_epoch) as success_time max(consecutive_failures) as fail_count by src_ip, username
| eval last_fail_time_fmt = strftime(last_fail_time, "%b %d %Y %I:%M:%S %p")
| eval success_time_fmt = strftime(success_time, "%b %d %Y %I:%M:%S %p")
| eval time_diff = success_time - last_fail_time
```
## Alert

![Screenshot 2025-05-15 175440](https://github.com/user-attachments/assets/0303d87c-131c-448e-bb91-68d2b56f8ba6)

