---
title: "Invalid Users Failing To Authenticate From Single Source Using NTLM"
aliases:
  - "/rule/56d62ef8-3462-4890-9859-7b41e541f8d5"
ruleid: 56d62ef8-3462-4890-9859-7b41e541f8d5

tags:
  - attack.t1110.003
  - attack.initial_access
  - attack.privilege_escalation



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects failed logins with multiple invalid domain accounts from a single source system using the NTLM protocol.

<!--more-->


## Known false-positives

* Terminal servers
* Jump servers
* Other multiuser systems like Citrix server farms
* Workstations with frequently changing users



## References

* https://docs.splunk.com/Documentation/ESSOC/3.22.0/stories/UseCase#Active_directory_password_spraying


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_failed_logons_single_source_ntlm2.yml))
```yaml
title: Invalid Users Failing To Authenticate From Single Source Using NTLM
id: 56d62ef8-3462-4890-9859-7b41e541f8d5
description: Detects failed logins with multiple invalid domain accounts from a single source system using the NTLM protocol.
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
        Status: '*0xC0000064' # The username you typed does not exist. Bad username.
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