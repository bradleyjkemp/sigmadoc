---
title: "Registry Persistence Mechanisms"
aliases:
  - "/rule/36803969-5421-41ec-b92f-8500f79c23b0"

tags:
  - attack.privilege_escalation
  - attack.persistence
  - attack.defense_evasion
  - attack.t1183
  - attack.t1546.012
  - car.2013-01-002





level: critical



date: Wed, 11 Apr 2018 15:13:00 +0200


---

Detects persistence registry keys

<!--more-->


## Known false-positives

* unknown



## References

* https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/


## Raw rule
```yaml
title: Registry Persistence Mechanisms
id: 36803969-5421-41ec-b92f-8500f79c23b0
description: Detects persistence registry keys
references:
    - https://oddvar.moe/2018/04/10/persistence-using-globalflags-in-image-file-execution-options-hidden-from-autoruns-exe/
date: 2018/04/11
modified: 2020/09/06
author: Karneades
logsource:
    category: registry_event
    product: windows
detection:
    selection_reg1:
        TargetObject:
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\\*\GlobalFlag'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\*\ReportingMode'
            - '*\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\\*\MonitorProcess'
        EventType: SetValue
    condition: selection_reg1
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.defense_evasion
    - attack.t1183 # an old one
    - attack.t1546.012
    - car.2013-01-002
falsepositives:
    - unknown
level: critical

```
