---
title: "UAC Bypass Using Windows Media Player - Process"
aliases:
  - "/rule/0058b9e5-bcd7-40d4-9205-95ca5a16d7b2"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_bypass_wmp.yml))
```yaml
title: UAC Bypass Using Windows Media Player - Process
id: 0058b9e5-bcd7-40d4-9205-95ca5a16d7b2
description: Detects the pattern of UAC Bypass using Windows Media Player osksupport.dll (UACMe 32)
author: Christian Burkard
date: 2021/08/23
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
    selection1:
        Image: 'C:\Program Files\Windows Media Player\osk.exe'
        IntegrityLevel:
          - 'High'
          - 'System'
    selection2:
        Image: 'C:\Windows\System32\cmd.exe'
        ParentCommandLine: '"C:\Windows\system32\mmc.exe" "C:\Windows\system32\eventvwr.msc" /s'
        IntegrityLevel:
          - 'High'
          - 'System'
    condition: 1 of selection*
falsepositives:
    - Unknown
level: high

```
