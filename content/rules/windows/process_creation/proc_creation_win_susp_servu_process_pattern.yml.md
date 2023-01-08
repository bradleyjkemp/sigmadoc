---
title: "Suspicious Serv-U Process Pattern"
aliases:
  - "/rule/58f4ea09-0fc2-4520-ba18-b85c540b0eaf"
ruleid: 58f4ea09-0fc2-4520-ba18-b85c540b0eaf

tags:
  - attack.credential_access
  - attack.t1555
  - cve.2021.35211



status: experimental





date: Wed, 14 Jul 2021 08:35:25 +0200


---

Detects a suspicious process pattern which could be a sign of an exploited Serv-U service

<!--more-->


## Known false-positives

* Legitimate uses in which users or programs use the SSH service of Serv-U for remote command execution



## References

* https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_servu_process_pattern.yml))
```yaml
title: Suspicious Serv-U Process Pattern
id: 58f4ea09-0fc2-4520-ba18-b85c540b0eaf
status: experimental
description: Detects a suspicious process pattern which could be a sign of an exploited Serv-U service
author: Florian Roth
date: 2021/07/14
references:
    - https://www.microsoft.com/security/blog/2021/07/13/microsoft-discovers-threat-actor-targeting-solarwinds-serv-u-software-with-0-day-exploit/
logsource:
    category: process_creation
    product: windows
tags:
    - attack.credential_access
    - attack.t1555 
    - cve.2021.35211
detection:
    selection:
        ParentImage|endswith: '\Serv-U.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\wscript.exe'
            - '\cscript.exe'
            - '\sh.exe'
            - '\bash.exe'
            - '\schtasks.exe'
            - '\regsvr32.exe'
            - '\wmic.exe'  # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '\mshta.exe'
            - '\rundll32.exe'
            - '\msiexec.exe'
            - '\forfiles.exe'
            - '\scriptrunner.exe'
    condition: selection
falsepositives:
    - Legitimate uses in which users or programs use the SSH service of Serv-U for remote command execution
level: critical

```
