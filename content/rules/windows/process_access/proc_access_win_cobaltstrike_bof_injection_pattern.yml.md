---
title: "CobaltStrike BOF Injection Pattern"
aliases:
  - "/rule/09706624-b7f6-455d-9d02-adee024cee1d"


tags:
  - attack.execution
  - attack.t1106
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Wed, 4 Aug 2021 11:28:58 +0200


---

Detects a typical pattern of a CobaltStrike BOF which inject into other processes

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/boku7/injectAmsiBypass
* https://github.com/boku7/spawn


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_access/proc_access_win_cobaltstrike_bof_injection_pattern.yml))
```yaml
title: CobaltStrike BOF Injection Pattern
id: 09706624-b7f6-455d-9d02-adee024cee1d
description: Detects a typical pattern of a CobaltStrike BOF which inject into other processes
references:
    - https://github.com/boku7/injectAmsiBypass
    - https://github.com/boku7/spawn
status: experimental
author: Christian Burkard
date: 2021/08/04
logsource:
    category: process_access
    product: windows
detection:
    selection:
        CallTrace|re: '^C:\\\\Windows\\\\SYSTEM32\\\\ntdll\\.dll\+[a-z0-9]{4,6}\|C:\\\\Windows\\\\System32\\\\KERNELBASE\\.dll\+[a-z0-9]{4,6}\|UNKNOWN\([A-Z0-9]{16}\)$'
        GrantedAccess:
          - '0x1028'
          - '0x1fffff'
    condition: selection
falsepositives:
    - unknown
level: high
tags:
    - attack.execution
    - attack.t1106
    - attack.defense_evasion
    - attack.t1562.001

```
