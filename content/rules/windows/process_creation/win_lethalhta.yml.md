---
title: "MSHTA Spwaned by SVCHOST"
aliases:
  - "/rule/ed5d72a6-f8f4-479d-ba79-02f6a80d7471"

tags:
  - attack.defense_evasion
  - attack.t1218.005
  - attack.execution
  - attack.t1170



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report

<!--more-->


## Known false-positives

* Unknown



## References

* https://codewhitesec.blogspot.com/2018/07/lethalhta.html


## Raw rule
```yaml
title: MSHTA Spwaned by SVCHOST
id: ed5d72a6-f8f4-479d-ba79-02f6a80d7471
status: experimental
description: Detects MSHTA.EXE spwaned by SVCHOST as seen in LethalHTA and described in report
references:
    - https://codewhitesec.blogspot.com/2018/07/lethalhta.html
tags:
    - attack.defense_evasion
    - attack.t1218.005
    - attack.execution  # an old one
    - attack.t1170  # an old one
author: Markus Neis
date: 2018/06/07
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\svchost.exe'
        Image: '*\mshta.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
