---
title: "Multiple Users Remotely Failing To Authenticate From Single Source"
aliases:
  - "/rule/add2ef8d-dc91-4002-9e7e-f2702369f53a"


tags:
  - attack.t1110.003
  - attack.initial_access
  - attack.privilege_escalation



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a source system failing to authenticate against a remote host with multiple users.

<!--more-->


## Known false-positives

* Terminal servers
* Jump servers
* Other multiuser systems like Citrix server farms
* Workstations with frequently changing users



## References

* https://docs.splunk.com/Documentation/ESSOC/3.22.0/stories/UseCase#Active_directory_password_spraying


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_failed_remote_logons_single_source.yml))
```yaml
title: Multiple Users Remotely Failing To Authenticate From Single Source
id: add2ef8d-dc91-4002-9e7e-f2702369f53a
description: Detects a source system failing to authenticate against a remote host with multiple users.
status: experimental
author: Mauricio Velazco
references:
    - https://docs.splunk.com/Documentation/ESSOC/3.22.0/stories/UseCase#Active_directory_password_spraying
date: 2021/06/01
modified: 2021/07/09
tags:
    - attack.t1110.003
    - attack.initial_access
    - attack.privilege_escalation
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4625
        LogonType: 3
    filter:
        IpAddress: '-'
    timeframe: 24h
    condition:
        - selection1 and not filter | count(TargetUserName) by IpAddress > 10
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users
level: medium

```
