---
title: "RottenPotato Like Attack Pattern"
aliases:
  - "/rule/16f5d8ca-44bd-47c8-acbe-6fc95a16c12f"

tags:
  - attack.privilege_escalation
  - attack.credential_access
  - attack.t1171
  - attack.t1557.001



date: Fri, 15 Nov 2019 11:44:18 +0100


---

Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/SBousseaden/status/1195284233729777665


## Raw rule
```yaml
title: RottenPotato Like Attack Pattern
id: 16f5d8ca-44bd-47c8-acbe-6fc95a16c12f
status: experimental
description: Detects logon events that have characteristics of events generated during an attack with RottenPotato and the like
references:
    - https://twitter.com/SBousseaden/status/1195284233729777665
author: "@SBousseaden, Florian Roth"
date: 2019/11/15
tags:
    - attack.privilege_escalation
    - attack.credential_access
    - attack.t1171          # an old one
    - attack.t1557.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 3
        TargetUserName: 'ANONYMOUS_LOGON'
        WorkstationName: '-'
        SourceNetworkAddress: '127.0.0.1'
    condition: selection
falsepositives:
    - Unknown
level: high

```