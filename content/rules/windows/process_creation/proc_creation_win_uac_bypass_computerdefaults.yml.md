---
title: "UAC Bypass Using ComputerDefaults"
aliases:
  - "/rule/3c05e90d-7eba-4324-9972-5d7f711a60a8"
ruleid: 3c05e90d-7eba-4324-9972-5d7f711a60a8

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 16:23:32 +0200


---

Detects the pattern of UAC Bypass using computerdefaults.exe (UACMe 59)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_bypass_computerdefaults.yml))
```yaml
title: UAC Bypass Using ComputerDefaults
id: 3c05e90d-7eba-4324-9972-5d7f711a60a8
description: Detects the pattern of UAC Bypass using computerdefaults.exe (UACMe 59)
author: Christian Burkard
date: 2021/08/31
status: experimental
references:
    - https://github.com/hfiref0x/UACME
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        IntegrityLevel:
            - 'High'
            - 'System'
        Image: 'C:\Windows\System32\ComputerDefaults.exe'
    filter:
        ParentImage|contains:
            - ':\Windows\System32'
            - ':\Program Files'
    condition: selection and not filter
falsepositives:
    - Unknown
level: high

```
