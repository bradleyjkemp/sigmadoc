---
title: "Failed Logins with Different Accounts from Single Source System"
aliases:
  - "/rule/fc947f8e-ea81-4b14-9a7b-13f888f94e18"



status: experimental



level: medium



date: Tue, 27 Dec 2016 14:49:54 +0100


---

Detects suspicious failed logins with different user accounts from a single source system

<!--more-->


## Known false-positives

* Terminal servers
* Jump servers
* Workstations with frequently changing users




## Raw rule
```yaml
title: Failed Logins with Different Accounts from Single Source System
id: fc947f8e-ea81-4b14-9a7b-13f888f94e18
status: experimental
description: Detects suspicious failed logins with different user accounts from a single source system
author: Florian Roth
date: 2017/02/16
logsource:
    product: linux
    service: auth
detection:
    selection:
        pam_message: authentication failure
        pam_user: '*'
        pam_rhost: '*'
    timeframe: 24h
    condition: selection | count(pam_user) by pam_rhost > 3
falsepositives:
    - Terminal servers
    - Jump servers
    - Workstations with frequently changing users
level: medium

```
