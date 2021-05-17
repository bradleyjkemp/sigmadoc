---
title: "Cisco File Deletion"
aliases:
  - "/rule/71d65515-c436-43c0-841b-236b1f32c21e"

tags:
  - attack.defense_evasion
  - attack.impact
  - attack.t1107
  - attack.t1070.004
  - attack.t1488
  - attack.t1561.001
  - attack.t1487
  - attack.t1561.002



status: experimental



level: medium



date: Thu, 14 Nov 2019 20:55:28 +0100


---

See what files are being deleted from flash file systems

<!--more-->


## Known false-positives

* Will be used sometimes by admins to clean up local flash space




## Raw rule
```yaml
title: Cisco File Deletion
id: 71d65515-c436-43c0-841b-236b1f32c21e
status: experimental
description: See what files are being deleted from flash file systems
author: Austin Clark
date: 2019/08/12
logsource:
    product: cisco
    service: aaa
    category: accounting
fields:
    - CmdSet
detection:
    keywords:
        - 'erase'
        - 'delete'
        - 'format'
    condition: keywords
falsepositives:
    - Will be used sometimes by admins to clean up local flash space
level: medium
tags:
    - attack.defense_evasion
    - attack.impact
    - attack.t1107          # an old one
    - attack.t1070.004
    - attack.t1488          # an old one
    - attack.t1561.001
    - attack.t1487          # an old one
    - attack.t1561.002
```
