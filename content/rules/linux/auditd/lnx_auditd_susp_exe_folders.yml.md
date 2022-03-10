---
title: "Program Executions in Suspicious Folders"
aliases:
  - "/rule/a39d7fa7-3fbd-4dc2-97e1-d87f546b1bbc"


tags:
  - attack.t1587
  - attack.t1584
  - attack.resource_development



status: test





date: Tue, 23 Jan 2018 11:13:05 +0100


---

Detects program executions in suspicious non-program folders related to malware or hacking activity

<!--more-->


## Known false-positives

* Admin activity (especially in /tmp folders)
* Crazy web applications



## References

* Internal Research


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_susp_exe_folders.yml))
```yaml
title: Program Executions in Suspicious Folders
id: a39d7fa7-3fbd-4dc2-97e1-d87f546b1bbc
status: test
description: Detects program executions in suspicious non-program folders related to malware or hacking activity
author: Florian Roth
references:
  - Internal Research
date: 2018/01/23
modified: 2021/11/27
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: 'SYSCALL'
    exe|startswith:
            # Temporary folder
      - '/tmp/'
            # Web server 
      - '/var/www/'                    # Standard
      - '/home/*/public_html/'         # Per-user
      - '/usr/local/apache2/'          # Classical Apache
      - '/usr/local/httpd/'            # Old SuSE Linux 6.* Apache
      - '/var/apache/'                 # Solaris Apache
      - '/srv/www/'                    # SuSE Linux 9.*
      - '/home/httpd/html/'            # Redhat 6 or older Apache
      - '/srv/http/'                   # ArchLinux standard
      - '/usr/share/nginx/html/'       # ArchLinux nginx
            # Data dirs of typically exploited services (incomplete list)
      - '/var/lib/pgsql/data/'
      - '/usr/local/mysql/data/'
      - '/var/lib/mysql/'
      - '/var/vsftpd/'
      - '/etc/bind/'
      - '/var/named/'
  condition: selection
falsepositives:
  - Admin activity (especially in /tmp folders)
  - Crazy web applications
level: medium
tags:
  - attack.t1587
  - attack.t1584
  - attack.resource_development

```