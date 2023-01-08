---
title: "UAC Bypass Using MSConfig Token Modification - File"
aliases:
  - "/rule/41bb431f-56d8-4691-bb56-ed34e390906f"
ruleid: 41bb431f-56d8-4691-bb56-ed34e390906f

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_uac_bypass_msconfig_gui.yml))
```yaml
title: UAC Bypass Using MSConfig Token Modification - File
id: 41bb431f-56d8-4691-bb56-ed34e390906f
description: Detects the pattern of UAC Bypass using a msconfig GUI hack (UACMe 55)
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
    category: file_event
    product: windows
detection:
    selection:
        TargetFilename|startswith: 'C:\Users\'
        TargetFilename|endswith: '\AppData\Local\Temp\pkgmgr.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
