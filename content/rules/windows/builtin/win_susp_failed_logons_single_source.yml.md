---
title: "Failed Logins with Different Accounts from Single Source System"
aliases:
  - "/rule/e98374a6-e2d9-4076-9b5c-11bdb2569995"

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1078



date: Tue, 27 Dec 2016 14:49:54 +0100


---

Detects suspicious failed logins with different user accounts from a single source system

<!--more-->


## Known false-positives

* Terminal servers
* Jump servers
* Other multiuser systems like Citrix server farms
* Workstations with frequently changing users




## Raw rule
```yaml
title: Failed Logins with Different Accounts from Single Source System
id: e98374a6-e2d9-4076-9b5c-11bdb2569995
description: Detects suspicious failed logins with different user accounts from a single source system
author: Florian Roth
date: 2017/01/10
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID:
            - 529
            - 4625
        UserName: '*'
        WorkstationName: '*'
    selection2:
        EventID: 4776
        UserName: '*'
        Workstation: '*'
    timeframe: 24h
    condition:
        - selection1 | count(UserName) by WorkstationName > 3
        - selection2 | count(UserName) by Workstation > 3
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users
level: medium

```
