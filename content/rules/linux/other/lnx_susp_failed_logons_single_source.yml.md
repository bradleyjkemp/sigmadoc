---
title: "Failed Logins with Different Accounts from Single Source System"
aliases:
  - "/rule/fc947f8e-ea81-4b14-9a7b-13f888f94e18"
ruleid: fc947f8e-ea81-4b14-9a7b-13f888f94e18

tags:
  - attack.credential_access
  - attack.t1110



status: test





date: Tue, 27 Dec 2016 14:49:54 +0100


---

Detects suspicious failed logins with different user accounts from a single source system

<!--more-->


## Known false-positives

* Terminal servers
* Jump servers
* Workstations with frequently changing users




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/other/lnx_susp_failed_logons_single_source.yml))
```yaml
title: Failed Logins with Different Accounts from Single Source System
id: fc947f8e-ea81-4b14-9a7b-13f888f94e18
status: test
description: Detects suspicious failed logins with different user accounts from a single source system
author: Florian Roth
date: 2017/02/16
modified: 2021/11/27
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
tags:
  - attack.credential_access
  - attack.t1110

```
