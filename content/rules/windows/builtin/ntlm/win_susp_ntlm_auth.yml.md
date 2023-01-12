---
title: "NTLM Logon"
aliases:
  - "/rule/98c3bcf1-56f2-49dc-9d8d-c66cf190238b"
ruleid: 98c3bcf1-56f2-49dc-9d8d-c66cf190238b

tags:
  - attack.lateral_movement
  - attack.t1550.002



status: experimental





date: Fri, 8 Jun 2018 11:45:49 +0200


---

Detects logons using NTLM, which could be caused by a legacy source or attackers

<!--more-->


## Known false-positives

* Legacy hosts



## References

* https://twitter.com/JohnLaTwC/status/1004895028995477505
* https://goo.gl/PsqrhT


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/ntlm/win_susp_ntlm_auth.yml))
```yaml
title: NTLM Logon
id: 98c3bcf1-56f2-49dc-9d8d-c66cf190238b
status: experimental
description: Detects logons using NTLM, which could be caused by a legacy source or attackers
references:
    - https://twitter.com/JohnLaTwC/status/1004895028995477505
    - https://goo.gl/PsqrhT
author: Florian Roth
date: 2018/06/08
modified: 2021/11/20
tags:
    - attack.lateral_movement
    - attack.t1550.002
logsource:
    product: windows
    service: ntlm
    definition: Requires events from Microsoft-Windows-NTLM/Operational
detection:
    selection:
        EventID: 8002
        ProcessName: '*'  # We use this to avoid false positives with ID 8002 on other log sources if the logsource isn't set correctly
    condition: selection
falsepositives:
    - Legacy hosts
level: low

```