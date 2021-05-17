---
title: "Cisco Denial of Service"
aliases:
  - "/rule/d94a35f0-7a29-45f6-90a0-80df6159967c"

tags:
  - attack.impact
  - attack.t1495
  - attack.t1529
  - attack.t1492
  - attack.t1565.001



status: experimental



level: medium



date: Thu, 14 Nov 2019 20:55:28 +0100


---

Detect a system being shutdown or put into different boot mode

<!--more-->


## Known false-positives

* Legitimate administrators may run these commands, though rarely.




## Raw rule
```yaml
title: Cisco Denial of Service
id: d94a35f0-7a29-45f6-90a0-80df6159967c
status: experimental
description: Detect a system being shutdown or put into different boot mode
author: Austin Clark
date: 2019/08/15
modified: 2020/09/02
logsource:
    product: cisco
    service: aaa
    category: accounting
fields:
    - CmdSet
detection:
    keywords:
        - 'shutdown'
        - 'config-register 0x2100'
        - 'config-register 0x2142'
    condition: keywords
falsepositives:
    - Legitimate administrators may run these commands, though rarely.
level: medium
tags:
    - attack.impact
    - attack.t1495
    - attack.t1529
    - attack.t1492          # an old one
    - attack.t1565.001
```
