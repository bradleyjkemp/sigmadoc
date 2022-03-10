---
title: "UAC Bypass Using DismHost"
aliases:
  - "/rule/853e74f9-9392-4935-ad3b-2e8c040dae86"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using DismHost DLL hijacking (UACMe 63)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_bypass_dismhost.yml))
```yaml
title: UAC Bypass Using DismHost
id: 853e74f9-9392-4935-ad3b-2e8c040dae86
description: Detects the pattern of UAC Bypass using DismHost DLL hijacking (UACMe 63)
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
        ParentImage|contains|all:
            - 'C:\Users\'
            - '\AppData\Local\Temp\'
            - '\DismHost.exe'
        IntegrityLevel:
          - 'High'
          - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```
