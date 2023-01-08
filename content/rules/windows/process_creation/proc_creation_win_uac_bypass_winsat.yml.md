---
title: "UAC Bypass Abusing Winsat Path Parsing - Process"
aliases:
  - "/rule/7a01183d-71a2-46ad-ad5c-acd989ac1793"
ruleid: 7a01183d-71a2-46ad-ad5c-acd989ac1793

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_bypass_winsat.yml))
```yaml
title: UAC Bypass Abusing Winsat Path Parsing - Process
id: 7a01183d-71a2-46ad-ad5c-acd989ac1793
description: Detects the pattern of UAC Bypass using a path parsing issue in winsat.exe (UACMe 52)
author: Christian Burkard
date: 2021/08/30
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
        ParentImage|endswith: '\AppData\Local\Temp\system32\winsat.exe'
        ParentCommandLine|contains: 'C:\Windows \system32\winsat.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
