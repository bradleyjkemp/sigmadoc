---
title: "CrashControl CrashDump Disabled"
aliases:
  - "/rule/2ff692c2-4594-41ec-8fcb-46587de769e0"
ruleid: 2ff692c2-4594-41ec-8fcb-46587de769e0

tags:
  - attack.t1564
  - attack.t1112



status: experimental





date: Thu, 24 Feb 2022 15:55:36 +0100


---

Detects disabling the CrashDump per registry (as used by HermeticWiper)

<!--more-->


## Known false-positives

* Legitimate disabling of crashdumps



## References

* https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_crashdump_disabled.yml))
```yaml
title: CrashControl CrashDump Disabled
id: 2ff692c2-4594-41ec-8fcb-46587de769e0
status: experimental
description: Detects disabling the CrashDump per registry (as used by HermeticWiper)
author: Tobias Michalski
date: 2022/02/24
references:
    - https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/
tags:
    - attack.t1564
    - attack.t1112
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|contains: 'SYSTEM\CurrentControlSet\Control\CrashControl'
        Details: 'DWORD (0x00000000)'
    condition: selection
falsepositives:
    - Legitimate disabling of crashdumps
level: medium

```
