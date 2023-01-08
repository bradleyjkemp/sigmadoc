---
title: "Suspicious Service Binary Directory"
aliases:
  - "/rule/883faa95-175a-4e22-8181-e5761aeb373c"
ruleid: 883faa95-175a-4e22-8181-e5761aeb373c

tags:
  - attack.defense_evasion
  - attack.t1202



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a service binary running in a suspicious directory

<!--more-->


## Known false-positives

* Unknown



## References

* https://blog.truesec.com/2021/03/07/exchange-zero-day-proxylogon-and-hafnium/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_service_dir.yml))
```yaml
title: Suspicious Service Binary Directory
id: 883faa95-175a-4e22-8181-e5761aeb373c
description: Detects a service binary running in a suspicious directory
author: Florian Roth
date: 2021/03/09
status: experimental
references:
    - https://blog.truesec.com/2021/03/07/exchange-zero-day-proxylogon-and-hafnium/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains: 
            - '\Users\Public\'
            - '\$Recycle.bin'
            - '\Users\All Users\'
            - '\Users\Default\'
            - '\Users\Contacts\'
            - '\Users\Searches\' 
            - 'C:\Perflogs\'
            - '\config\systemprofile\'
            - '\Windows\Fonts\'
            - '\Windows\IME\'
            - '\Windows\addins\'
        ParentImage|endswith:
            - '\services.exe'
            - '\svchost.exe'
    condition: selection
falsepositives:
    - Unknown
level: high
tags:
    - attack.defense_evasion 
    - attack.t1202 
```
