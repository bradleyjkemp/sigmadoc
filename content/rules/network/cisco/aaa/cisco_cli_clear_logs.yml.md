---
title: "Cisco Clear Logs"
aliases:
  - "/rule/ceb407f6-8277-439b-951f-e4210e3ed956"

tags:
  - attack.defense_evasion
  - attack.t1146
  - attack.t1070.003



date: Thu, 14 Nov 2019 20:55:28 +0100


---

Clear command history in network OS which is used for defense evasion

<!--more-->


## Known false-positives

* Legitimate administrators may run these commands




## Raw rule
```yaml
title: Cisco Clear Logs
id: ceb407f6-8277-439b-951f-e4210e3ed956
status: experimental
description: Clear command history in network OS which is used for defense evasion
author: Austin Clark
date: 2019/08/12
modified: 2020/09/02
logsource:
    product: cisco
    service: aaa
    category: accounting
fields:
    - src
    - CmdSet
    - User
    - Privilege_Level
    - Remote_Address
detection:
    keywords:
        - 'clear logging'
        - 'clear archive'
    condition: keywords
falsepositives:
    - Legitimate administrators may run these commands
level: high
tags:
    - attack.defense_evasion
    - attack.t1146          # an old one
    - attack.t1070.003
```
