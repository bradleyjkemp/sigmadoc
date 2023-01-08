---
title: "Suspect Svchost Memory Asccess"
aliases:
  - "/rule/166e9c50-8cd9-44af-815d-d1f0c0e90dde"
ruleid: 166e9c50-8cd9-44af-815d-d1f0c0e90dde

tags:
  - attack.defense_evasion
  - attack.t1562.002



status: experimental





date: Thu, 2 Jan 2020 14:47:55 +0000


---

Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/hlldz/Invoke-Phant0m
* https://twitter.com/timbmsft/status/900724491076214784


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_invoke_phantom.yml))
```yaml
title: Suspect Svchost Memory Asccess
id: 166e9c50-8cd9-44af-815d-d1f0c0e90dde
status: experimental
description: Detects suspect access to svchost process memory such as that used by Invoke-Phantom to kill the winRM windows event logging service.
author: Tim Burrell
date: 2020/01/02
modified: 2021/10/21
references:
    - https://github.com/hlldz/Invoke-Phant0m
    - https://twitter.com/timbmsft/status/900724491076214784
tags:
    - attack.defense_evasion
    - attack.t1562.002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage|endswith: '\WINDOWS\System32\svchost.exe'
        GrantedAccess: '0x1F3FFF'
        CallTrace|contains: 'UNKNOWN'
    condition: selection
falsepositives:
    - unknown
level: high

```
