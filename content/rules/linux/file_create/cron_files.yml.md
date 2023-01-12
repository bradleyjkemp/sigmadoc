---
title: "Cron Files"
aliases:
  - "/rule/6c4e2f43-d94d-4ead-b64d-97e53fa2bd05"
ruleid: 6c4e2f43-d94d-4ead-b64d-97e53fa2bd05

tags:
  - attack.persistence
  - attack.t1053.003



status: experimental





date: Sat, 16 Oct 2021 02:33:01 -0400


---

Detects creation of cron files or files in Cron directories. Potential persistence.

<!--more-->


## Known false-positives

* Any legitimate cron file.



## References

* https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/attack-based/persistence/T1053.003_Cron_Activity.xml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/file_create/cron_files.yml))
```yaml
title: Cron Files
id: 6c4e2f43-d94d-4ead-b64d-97e53fa2bd05
status: experimental
description: Detects creation of cron files or files in Cron directories. Potential persistence.
date: 2021/10/15
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research), MSTIC
tags:
    - attack.persistence
    - attack.t1053.003
references:
   - https://github.com/microsoft/MSTIC-Sysmon/blob/main/linux/configs/attack-based/persistence/T1053.003_Cron_Activity.xml
logsource:
   product: linux
   category: file_create
detection:
   selection1:
      TargetFilename|startswith:
         - '/etc/cron.d/'
         - '/etc/cron.daily/'
         - '/etc/cron.hourly/'
         - '/etc/cron.monthly/'
         - '/etc/cron.weekly/'
         - '/var/spool/cron/crontabs/'
   selection2:   
      TargetFilename|contains:
         - '/etc/cron.allow'
         - '/etc/cron.deny'
         - '/etc/crontab'
   condition: selection1 or selection2
falsepositives:
   - Any legitimate cron file.
level: medium
            
```