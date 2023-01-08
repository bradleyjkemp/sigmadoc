---
title: "Disabled Users Failing To Authenticate From Source Using Kerberos"
aliases:
  - "/rule/4b6fe998-b69c-46d8-901b-13677c9fb663"
ruleid: 4b6fe998-b69c-46d8-901b-13677c9fb663

tags:
  - attack.t1110.003
  - attack.initial_access
  - attack.privilege_escalation



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects failed logins with multiple disabled domain accounts from a single source system using the Kerberos protocol.

<!--more-->


## Known false-positives

* Vulnerability scanners
* Misconfigured systems
* Remote administration tools
* VPN terminators
* Multiuser systems like Citrix server farms



## References

* https://docs.splunk.com/Documentation/ESSOC/3.22.0/stories/UseCase#Active_directory_password_spraying


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_failed_logons_single_source_kerberos2.yml))
```yaml
title: Disabled Users Failing To Authenticate From Source Using Kerberos
id: 4b6fe998-b69c-46d8-901b-13677c9fb663
description: Detects failed logins with multiple disabled domain accounts from a single source system using the Kerberos protocol.
status: experimental
author: Mauricio Velazco, frack113
date: 2021/06/01
modified: 2021/07/06
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
    selection:
        EventID: 4768
        Status: '0x12'
    filter_computer:
        TargetUserName|endswith: '$'
    timeframe: 24h
    condition:
        - selection and not filter_computer | count(TargetUserName) by IpAddress > 10
falsepositives:
    - Vulnerability scanners
    - Misconfigured systems
    - Remote administration tools
    - VPN terminators
    - Multiuser systems like Citrix server farms
level: medium

```
