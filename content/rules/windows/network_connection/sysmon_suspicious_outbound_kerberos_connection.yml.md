---
title: "Suspicious Outbound Kerberos Connection"
aliases:
  - "/rule/e54979bd-c5f9-4d6c-967b-a04b19ac4c74"

tags:
  - attack.credential_access
  - attack.t1558
  - attack.t1208
  - attack.lateral_movement
  - attack.t1550.003
  - attack.t1097



status: experimental



level: high



date: Tue, 29 Oct 2019 03:44:22 +0300


---

Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.

<!--more-->


## Known false-positives

* Other browsers



## References

* https://github.com/GhostPack/Rubeus


## Raw rule
```yaml
title: Suspicious Outbound Kerberos Connection
id: e54979bd-c5f9-4d6c-967b-a04b19ac4c74
status: experimental
description: Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.
references:
    - https://github.com/GhostPack/Rubeus
author: Ilyas Ochkov, oscd.community
date: 2019/10/24
modified: 2020/08/24
tags:
    - attack.credential_access
    - attack.t1558
    - attack.t1208  # an old one
    - attack.lateral_movement
    - attack.t1550.003
    - attack.t1097  # an old one
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        DestinationPort: 88
        Initiated: 'true'
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
