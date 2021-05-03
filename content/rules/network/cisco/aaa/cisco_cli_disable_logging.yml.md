---
title: "Cisco Disabling Logging"
aliases:
  - "/rule/9e8f6035-88bf-4a63-96b6-b17c0508257e"

tags:
  - attack.defense_evasion
  - attack.t1089
  - attack.t1562.001



date: Thu, 14 Nov 2019 20:55:28 +0100


---

Turn off logging locally or remote

<!--more-->


## Known false-positives

* Unknown




## Raw rule
```yaml
title: Cisco Disabling Logging
id: 9e8f6035-88bf-4a63-96b6-b17c0508257e
status: experimental
description: Turn off logging locally or remote
author: Austin Clark
date: 2019/08/11
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
        - 'no logging'
        - 'no aaa new-model'
    condition: keywords
falsepositives:
    - Unknown
level: high
tags:
    - attack.defense_evasion
    - attack.t1089          # an old one
    - attack.t1562.001
```
