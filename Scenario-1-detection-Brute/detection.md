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

## Event ID / Data Source Mapping



## Detection Logic / Query (Splunk SPL)


