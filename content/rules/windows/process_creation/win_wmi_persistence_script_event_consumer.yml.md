---
title: "WMI Persistence - Script Event Consumer"
aliases:
  - "/rule/ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e"

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1546.003
  - attack.t1047



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects WMI script event consumers

<!--more-->


## Known false-positives

* Legitimate event consumers



## References

* https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/


## Raw rule
```yaml
title: WMI Persistence - Script Event Consumer
id: ec1d5e28-8f3b-4188-a6f8-6e8df81dc28e
status: experimental
description: Detects WMI script event consumers
references:
    - https://www.eideon.com/2018-03-02-THL03-WMIBackdoors/
author: Thomas Patzke
date: 2018/03/07
modified: 2020/08/29
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1546.003
    - attack.t1047 # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: C:\WINDOWS\system32\wbem\scrcons.exe
        ParentImage: C:\Windows\System32\svchost.exe
    condition: selection
falsepositives:
    - Legitimate event consumers
level: high

```
