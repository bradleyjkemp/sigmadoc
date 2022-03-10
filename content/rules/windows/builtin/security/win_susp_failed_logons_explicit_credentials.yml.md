---
title: "Multiple Users Attempting To Authenticate Using Explicit Credentials"
aliases:
  - "/rule/196a29c2-e378-48d8-ba07-8a9e61f7fab9"


tags:
  - attack.t1110.003
  - attack.initial_access
  - attack.privilege_escalation



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a source user failing to authenticate with multiple users using explicit credentials on a host.

<!--more-->


## Known false-positives

* Terminal servers
* Jump servers
* Other multiuser systems like Citrix server farms
* Workstations with frequently changing users



## References

* https://docs.splunk.com/Documentation/ESSOC/3.22.0/stories/UseCase#Active_directory_password_spraying


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_failed_logons_explicit_credentials.yml))
```yaml
title: Multiple Users Attempting To Authenticate Using Explicit Credentials
id: 196a29c2-e378-48d8-ba07-8a9e61f7fab9
description: Detects a source user failing to authenticate with multiple users using explicit credentials on a host.
status: experimental
author: Mauricio Velazco
date: 2021/06/01
modified: 2021/08/09
references:
    - https://docs.splunk.com/Documentation/ESSOC/3.22.0/stories/UseCase#Active_directory_password_spraying
tags:
    - attack.t1110.003
    - attack.initial_access
    - attack.privilege_escalation
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4648
    timeframe: 24h
    condition:
        - selection1 | count(Account_Name) by ComputerName > 10
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users
level: medium

```