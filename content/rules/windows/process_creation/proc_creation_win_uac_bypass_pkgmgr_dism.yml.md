---
title: "UAC Bypass Using PkgMgr and DISM"
aliases:
  - "/rule/a743ceba-c771-4d75-97eb-8a90f7f4844c"


tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using pkgmgr.exe and dism.exe (UACMe 23)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uac_bypass_pkgmgr_dism.yml))
```yaml
title: UAC Bypass Using PkgMgr and DISM
id: a743ceba-c771-4d75-97eb-8a90f7f4844c
description: Detects the pattern of UAC Bypass using pkgmgr.exe and dism.exe (UACMe 23)
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
    selection:
        ParentImage|endswith: '\pkgmgr.exe'
        Image|endswith: '\dism.exe'
        IntegrityLevel:
          - 'High'
          - 'System'
    condition: selection
falsepositives:
    - Unknown
level: high

```
