---
title: "Valid Users Failing to Authenticate from Single Source Using NTLM"
aliases:
  - "/rule/f88bab7f-b1f4-41bb-bdb1-4b8af35b0470"
ruleid: f88bab7f-b1f4-41bb-bdb1-4b8af35b0470

tags:
  - attack.t1110.003
  - attack.initial_access
  - attack.privilege_escalation



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects failed logins with multiple valid domain accounts from a single source system using the NTLM protocol.

<!--more-->


## Known false-positives

* Terminal servers
* Jump servers
* Other multiuser systems like Citrix server farms
* Workstations with frequently changing users



## References

* https://docs.splunk.com/Documentation/ESSOC/3.22.0/stories/UseCase#Active_directory_password_spraying


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_failed_logons_single_source_ntlm.yml))
```yaml
title: Valid Users Failing to Authenticate from Single Source Using NTLM
id: f88bab7f-b1f4-41bb-bdb1-4b8af35b0470
description: Detects failed logins with multiple valid domain accounts from a single source system using the NTLM protocol.
status: experimental
author: Mauricio Velazco
date: 2021/06/01
modified: 2021/07/07
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
        EventID: 4776
        Status: '*0xC000006A' #Account logon with misspelled or bad password.
    filter:
        TargetUserName: '*$'
    timeframe: 24h
    condition:
        - selection1 and not filter | count(TargetUserName) by Workstation > 10
falsepositives:
    - Terminal servers
    - Jump servers
    - Other multiuser systems like Citrix server farms
    - Workstations with frequently changing users
level: medium

```
