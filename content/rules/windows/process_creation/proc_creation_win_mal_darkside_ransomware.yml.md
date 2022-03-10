---
title: "DarkSide Ransomware Pattern"
aliases:
  - "/rule/965fff6c-1d7e-4e25-91fd-cdccd75f7d2c"


tags:
  - attack.execution
  - attack.t1204



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects DarkSide Ransomware and helpers

<!--more-->


## Known false-positives

* Unknown
* UAC bypass method used by other malware



## References

* https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html
* https://app.any.run/tasks/8b9a571b-bcc1-4783-ba32-df4ba623b9c0/
* https://www.joesandbox.com/analysis/411752/0/html#7048BB9A06B8F2DD9D24C77F389D7B2B58D2


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_mal_darkside_ransomware.yml))
```yaml
title: DarkSide Ransomware Pattern
id: 965fff6c-1d7e-4e25-91fd-cdccd75f7d2c
author: Florian Roth
date: 2021/05/14
description: Detects DarkSide Ransomware and helpers
status: experimental
references:
    - https://www.fireeye.com/blog/threat-research/2021/05/shining-a-light-on-darkside-ransomware-operations.html
    - https://app.any.run/tasks/8b9a571b-bcc1-4783-ba32-df4ba623b9c0/
    - https://www.joesandbox.com/analysis/411752/0/html#7048BB9A06B8F2DD9D24C77F389D7B2B58D2
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: 
            - '=[char][byte](''0x''+'
            - ' -work worker0 -path '
    selection2:
        ParentCommandLine|contains: 'DllHost.exe /Processid:{3E5FC7F9-9A51-4367-9063-A120244FBEC7}'
        Image|contains: '\AppData\Local\Temp\'
    condition: 1 of selection*
falsepositives:
    - Unknown
    - UAC bypass method used by other malware
level: critical
tags:
    - attack.execution
    - attack.t1204

```
