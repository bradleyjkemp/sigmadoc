---
title: "Suspicious Remote Logon with Explicit Credentials"
aliases:
  - "/rule/941e5c45-cda7-4864-8cea-bbb7458d194a"


tags:
  - attack.t1078
  - attack.lateral_movement



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious processes logging on with explicit credentials

<!--more-->


## Known false-positives

* Administrators that use the RunAS command or scheduled tasks



## References

* https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_logon_explicit_credentials.yml))
```yaml
title: Suspicious Remote Logon with Explicit Credentials
id: 941e5c45-cda7-4864-8cea-bbb7458d194a
status: experimental
description: Detects suspicious processes logging on with explicit credentials
references:
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view
author: 'oscd.community, Teymur Kheirkhabarov @HeirhabarovT, Zach Stanford @svch0st'
date: 2020/10/05
modified: 2021/11/12
tags:
    - attack.t1078
    - attack.lateral_movement
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4648
        ProcessName|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\winrs.exe'
            - '\wmic.exe'
            - '\net.exe'
            - '\net1.exe'
            - '\reg.exe'
    filter:
        TargetServerName: 'localhost'
    condition: selection and not filter
falsepositives:
    - Administrators that use the RunAS command or scheduled tasks
level: medium

```
