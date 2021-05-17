---
title: "Suspicious Outbound Kerberos Connection"
aliases:
  - "/rule/eca91c7c-9214-47b9-b4c5-cb1d7e4f2350"

tags:
  - attack.lateral_movement
  - attack.t1208
  - attack.t1558.003



status: experimental



level: high



date: Tue, 29 Oct 2019 03:44:22 +0300


---

Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.

<!--more-->


## Known false-positives

* Other browsers



## References

* https://github.com/GhostPack/Rubeus8


## Raw rule
```yaml
title: Suspicious Outbound Kerberos Connection
id: eca91c7c-9214-47b9-b4c5-cb1d7e4f2350
status: experimental
description: Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.
references:
    - https://github.com/GhostPack/Rubeus8
author: Ilyas Ochkov, oscd.community
date: 2019/10/24
modified: 2019/11/13
tags:
    - attack.lateral_movement
    - attack.t1208           # an old one
    - attack.t1558.003
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
        DestinationPort: 88
    filter:
        Image|endswith:
            - '\lsass.exe'
            - '\opera.exe'
            - '\chrome.exe'
            - '\firefox.exe'
    condition: selection and not filter
falsepositives:
    - Other browsers
level: high

```
