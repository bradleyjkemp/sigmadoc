---
title: "Netsh RDP Port Forwarding"
aliases:
  - "/rule/782d6f3e-4c5d-4b8c-92a3-1d05fed72e63"

tags:
  - attack.lateral_movement
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1090



---

Detects netsh commands that configure a port forwarding of port 3389 used for RDP

<!--more-->


## Known false-positives

* Legitimate administration



## References

* https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html


## Raw rule
```yaml
title: Netsh RDP Port Forwarding
id: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63
description: Detects netsh commands that configure a port forwarding of port 3389 used for RDP
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1090
status: experimental
author: Florian Roth
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - netsh i* p*=3389 c*
    condition: selection
falsepositives:
    - Legitimate administration
level: high

```
