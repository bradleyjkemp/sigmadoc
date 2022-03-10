---
title: "Multiple Users Failing to Authenticate from Single Process"
aliases:
  - "/rule/fe563ab6-ded4-4916-b49f-a3a8445fe280"


tags:
  - attack.t1110.003
  - attack.initial_access
  - attack.privilege_escalation



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects failed logins with multiple accounts from a single process on the system.

<!--more-->


## Known false-positives

* Terminal servers
* Jump servers
* Other multiuser systems like Citrix server farms
* Workstations with frequently changing users



## References

* https://docs.splunk.com/Documentation/ESSOC/3.22.0/stories/UseCase#Active_directory_password_spraying
* https://www.trimarcsecurity.com/single-post/2018/05/06/trimarc-research-detecting-password-spraying-with-security-event-auditing


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_failed_logons_single_process.yml))
```yaml
title: Multiple Users Failing to Authenticate from Single Process
id: fe563ab6-ded4-4916-b49f-a3a8445fe280
description: Detects failed logins with multiple accounts from a single process on the system.
status: experimental
author: Mauricio Velazco
date: 2021/06/01
modified: 2021/07/07
references:
    - https://docs.splunk.com/Documentation/ESSOC/3.22.0/stories/UseCase#Active_directory_password_spraying
    - https://www.trimarcsecurity.com/single-post/2018/05/06/trimarc-research-detecting-password-spraying-with-security-event-auditing
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
        LogonType: 2
    filter:
        ProcessName: '-'
    timeframe: 24h
    condition:
        - selection1 and not filter | count(TargetUserName) by ProcessName > 10
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users
level: medium

```