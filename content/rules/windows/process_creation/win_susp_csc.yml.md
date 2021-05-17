---
title: "Suspicious Parent of Csc.exe"
aliases:
  - "/rule/b730a276-6b63-41b8-bcf8-55930c8fc6ee"

tags:
  - attack.execution
  - attack.t1059.005
  - attack.t1059.007
  - attack.defense_evasion
  - attack.t1500
  - attack.t1218.005



status: experimental



level: high



---

Detects a suspicious parent of csc.exe, which could by a sign of payload delivery

<!--more-->


## Known false-positives

* Unkown



## References

* https://twitter.com/SBousseaden/status/1094924091256176641


## Raw rule
```yaml
title: Suspicious Parent of Csc.exe
id: b730a276-6b63-41b8-bcf8-55930c8fc6ee
description: Detects a suspicious parent of csc.exe, which could by a sign of payload delivery
status: experimental
references:
    - https://twitter.com/SBousseaden/status/1094924091256176641
author: Florian Roth
date: 2019/02/11
modified: 2020/09/05
tags:
    - attack.execution
    - attack.t1059.005
    - attack.t1059.007
    - attack.defense_evasion
    - attack.t1500
    - attack.t1218.005
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\csc.exe*'
        ParentImage:
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\mshta.exe'
    condition: selection
falsepositives:
    - Unkown
level: high

```
