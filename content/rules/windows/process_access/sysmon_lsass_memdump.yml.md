---
title: "LSASS Memory Dump"
aliases:
  - "/rule/5ef9853e-4d0e-4a70-846f-a9ca37d876da"

tags:
  - attack.credential_access
  - attack.t1003.001
  - attack.t1003
  - attack.s0002



status: experimental



level: high



date: Wed, 3 Apr 2019 13:51:59 +0200


---

Detects process LSASS memory dump using procdump or taskmgr based on the CallTrace pointing to dbghelp.dll or dbgcore.dll for win10

<!--more-->


## Known false-positives

* unknown



## References

* https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html


## Raw rule
```yaml
title: LSASS Memory Dump
id: 5ef9853e-4d0e-4a70-846f-a9ca37d876da
status: experimental
description: Detects process LSASS memory dump using procdump or taskmgr based on the CallTrace pointing to dbghelp.dll or dbgcore.dll for win10
author: Samir Bousseaden
date: 2019/04/03
modified: 2020/08/24
references:
    - https://blog.menasec.net/2019/02/threat-hunting-21-procdump-or-taskmgr.html
tags:
    - attack.credential_access
    - attack.t1003.001
    - attack.t1003  # an old one
    - attack.s0002
logsource:
    category: process_access
    product: windows
detection:
    selection:
        TargetImage: 'C:\windows\system32\lsass.exe'
        GrantedAccess: '0x1fffff'
        CallTrace:
         - '*dbghelp.dll*'
         - '*dbgcore.dll*'
    condition: selection
falsepositives:
    - unknown
level: high

```
