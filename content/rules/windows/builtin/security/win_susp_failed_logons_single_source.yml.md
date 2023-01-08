---
title: "Failed Logins with Different Accounts from Single Source System"
aliases:
  - "/rule/e98374a6-e2d9-4076-9b5c-11bdb2569995"
ruleid: e98374a6-e2d9-4076-9b5c-11bdb2569995

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1078



status: experimental





date: Tue, 27 Dec 2016 14:49:54 +0100


---

Detects suspicious failed logins with different user accounts from a single source system

<!--more-->


## Known false-positives

* Terminal servers
* Jump servers
* Other multiuser systems like Citrix server farms
* Workstations with frequently changing users




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_failed_logons_single_source.yml))
```yaml
title: Failed Logins with Different Accounts from Single Source System
id: e98374a6-e2d9-4076-9b5c-11bdb2569995
description: Detects suspicious failed logins with different user accounts from a single source system
status: experimental
author: Florian Roth
date: 2017/01/10
modified: 2021/09/21
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
        TargetUserName: '*'
        WorkstationName: '*'
    condition: selection1 | count(TargetUserName) by WorkstationName > 3    
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users
level: medium
```
