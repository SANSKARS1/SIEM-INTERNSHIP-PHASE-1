# Detection Use Case: Suspicious Login Attempt After Business Hours

## Scenario Description
A user logs into the Linux system outside standard working hours (valid login window: 9:00 AM to 7:00 PM). Such activity could indicate unauthorized or suspicious access.

## Objective
This detection aims to identify login events occurring outside of defined working hours (09:00–19:00), which may indicate lateral movement or unauthorized access attempts.

## Tools Used
- **SIEM**: Splunk Enterprise
- **Log Source**: Linux (`/var/log/auth.log`)
- **Lab Setup**:
  - Linux VM (Kali) running Splunk Universal Forwarder
  - Windows host running Splunk Enterprise
  - Logs monitored: `/var/log/auth.log`
  - Logs forwarded to Splunk via TCP port `9997`

---

## Event ID / Data Source Mapping

COMMAND	CWD	TTY	USER	_raw	_time	ampm	date_hour	date_mday	date_minute	date_month	date_second	date_wday	date_year	date_zone	event_type	eventtype	host	hour_12	hour_12_num	index	linecount	punct	source	sourcetype	splunk_server	splunk_server_group	time_12hr	timeendpos	timestartpos	uid
				2025-05-20T21:41:11.449974+05:30 kali su[1205]: pam_unix(su:session): session opened for user root(uid=0) by (uid=0)	2025-05-20T21:41:11.449+0530	PM	21	20	41	may	11	tuesday	2025	330	root_session		kali	09	9	linux_logs	1	--::.+:__[]:_(:):_____(=)__(=)	/var/log/auth.log	auth	KANHA		9:41:11 PM	32	0	0
				2025-05-20T21:41:11.718517+05:30 kali (systemd): pam_unix(systemd-user:session): session opened for user root(uid=0) by root(uid=0)	2025-05-20T21:41:11.718+0530	PM	21	20	41	may	11	tuesday	2025	330	root_session		kali	09	9	linux_logs	1	--::.+:__():_(-:):_____(=)__(=)	/var/log/auth.log	auth	KANHA		9:41:11 PM	32	0	0
				2025-05-20T21:42:53.609040+05:30 kali pkexec: pam_unix(polkit-1:session): session opened for user root(uid=0) by kali(uid=1000)	2025-05-20T21:42:53.609+0530	PM	21	20	42	may	53	tuesday	2025	330	root_session		kali	09	9	linux_logs	1	--::.+:__:_(-:):_____(=)__(=)	/var/log/auth.log	auth	KANHA		9:42:53 PM	32	0	0
/usr/bin/x-terminal-emulator	/home/kali	unknown	root	2025-05-20T21:42:53.615409+05:30 kali pkexec[2229]: kali: Executing command [USER=root] [TTY=unknown] [CWD=/home/kali] [COMMAND=/usr/bin/x-terminal-emulator]	2025-05-20T21:42:53.615+0530	PM	21	20	42	may	53	tuesday	2025	330	command_as_root		kali	09	9	linux_logs	1	--::.+:__[]:_:___[=]_[=]_[=//]_[=///--]	/var/log/auth.log	auth	KANHA		9:42:53 PM	32	0	
				2025-05-20T21:45:01.836709+05:30 kali CRON[3930]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)	2025-05-20T21:45:01.836+0530	PM	21	20	45	may	1	tuesday	2025	330	root_session		kali	09	9	linux_logs	1	--::.+:__[]:_(:):_____(=)__(=)	/var/log/auth.log	auth	KANHA		9:45:01 PM	32	0	0
![image](https://github.com/user-attachments/assets/b6b47e47-450e-484d-b6a3-87024f455c0b)



## Detection Logic / Query (Splunk SPL)
```spl


