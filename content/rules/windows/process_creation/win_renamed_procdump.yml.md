---
title: "Renamed ProcDump"
aliases:
  - "/rule/4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67"

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1036.003



status: experimental



level: critical



date: Mon, 18 Nov 2019 15:27:04 +0100


---

Detects the execution of a renamed ProcDump executable often used by attackers or malware

<!--more-->


## Known false-positives

* Procdump illegaly bundled with legitimate software
* Weird admins who renamed binaries



## References

* https://docs.microsoft.com/en-us/sysinternals/downloads/procdump


## Raw rule
```yaml
title: Renamed ProcDump
id: 4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67
status: experimental
description: Detects the execution of a renamed ProcDump executable often used by attackers or malware
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/procdump
author: Florian Roth
date: 2019/11/18
modified: 2020/09/06
tags:
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.003
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        OriginalFileName: 'procdump'
    filter:
        Image: 
            - '*\procdump.exe'
            - '*\procdump64.exe'
    condition: selection and not filter
falsepositives:
    - Procdump illegaly bundled with legitimate software
    - Weird admins who renamed binaries
level: critical

```
