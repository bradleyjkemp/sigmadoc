---
title: "Security Eventlog Cleared"
aliases:
  - "/rule/f2f01843-e7b8-4f95-a35a-d23584476423"

tags:
  - attack.defense_evasion
  - attack.t1070
  - attack.t1070.001
  - car.2016-04-002



date: Sat, 24 Dec 2016 12:23:47 +0100


---

Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities

<!--more-->


## Known false-positives

* Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)
* System provisioning (system reset before the golden image creation)




## Raw rule
```yaml
title: Security Eventlog Cleared
id: f2f01843-e7b8-4f95-a35a-d23584476423
description: Some threat groups tend to delete the local 'Security' Eventlog using certain utitlities
tags:
    - attack.defense_evasion
    - attack.t1070          # an old one
    - attack.t1070.001
    - car.2016-04-002
author: Florian Roth
date: 2017/02/19
modified: 2020/08/23
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 517
            - 1102
    condition: selection
falsepositives:
    - Rollout of log collection agents (the setup routine often includes a reset of the local Eventlog)
    - System provisioning (system reset before the golden image creation)
level: high

```
