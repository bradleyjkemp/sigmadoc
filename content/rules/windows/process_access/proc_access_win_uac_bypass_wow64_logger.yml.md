---
title: "UAC Bypass Using WOW64 Logger DLL Hijack"
aliases:
  - "/rule/4f6c43e2-f989-4ea5-bcd8-843b49a0317c"
ruleid: 4f6c43e2-f989-4ea5-bcd8-843b49a0317c

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002



status: experimental





date: Tue, 31 Aug 2021 12:45:07 +0200


---

Detects the pattern of UAC Bypass using a WoW64 logger DLL hijack (UACMe 30)

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/hfiref0x/UACME


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_uac_bypass_wow64_logger.yml))
```yaml
title: UAC Bypass Using WOW64 Logger DLL Hijack
id: 4f6c43e2-f989-4ea5-bcd8-843b49a0317c
description: Detects the pattern of UAC Bypass using a WoW64 logger DLL hijack (UACMe 30)
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
    category: process_access
    product: windows
detection:
    selection:
        SourceImage|contains: ':\Windows\SysWOW64\'
        GrantedAccess: '0x1fffff'
        CallTrace|startswith: 'UNKNOWN(0000000000000000)|UNKNOWN(0000000000000000)|'
    condition: selection
falsepositives:
    - Unknown
level: high

```
