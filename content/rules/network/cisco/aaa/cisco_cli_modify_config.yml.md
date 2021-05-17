---
title: "Cisco Modify Configuration"
aliases:
  - "/rule/671ffc77-50a7-464f-9e3d-9ea2b493b26b"

tags:
  - attack.persistence
  - attack.impact
  - attack.t1490
  - attack.t1505
  - attack.t1493
  - attack.t1565.002
  - attack.t1168
  - attack.t1053



status: experimental



level: medium



date: Thu, 14 Nov 2019 20:55:28 +0100


---

Modifications to a config that will serve an adversary's impacts or persistence

<!--more-->


## Known false-positives

* Legitimate administrators may run these commands




## Raw rule
```yaml
title: Cisco Modify Configuration
id: 671ffc77-50a7-464f-9e3d-9ea2b493b26b
status: experimental
description: Modifications to a config that will serve an adversary's impacts or persistence
author: Austin Clark
date: 2019/08/12
modified: 2020/09/02
logsource:
    product: cisco
    service: aaa
    category: accounting
fields:
    - CmdSet
detection:
    keywords:
        - 'ip http server'
        - 'ip https server'
        - 'kron policy-list'
        - 'kron occurrence'
        - 'policy-list'
        - 'access-list'
        - 'ip access-group'
        - 'archive maximum'
    condition: keywords
falsepositives:
    - Legitimate administrators may run these commands
level: medium
tags:
    - attack.persistence
    - attack.impact
    - attack.t1490
    - attack.t1505
    - attack.t1493          # an old one
    - attack.t1565.002
    - attack.t1168          # an old one
    - attack.t1053
```
