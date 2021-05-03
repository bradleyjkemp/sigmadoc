---
title: "Netsh Port Forwarding"
aliases:
  - "/rule/322ed9ec-fcab-4f67-9a34-e7c6aef43614"

tags:
  - attack.lateral_movement
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1090



---

Detects netsh commands that configure a port forwarding

<!--more-->


## Known false-positives

* Legitimate administration



## References

* https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html


## Raw rule
```yaml
title: Netsh Port Forwarding
id: 322ed9ec-fcab-4f67-9a34-e7c6aef43614
description: Detects netsh commands that configure a port forwarding
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/29
modified: 2020/09/01
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
            - netsh interface portproxy add v4tov4 *
    condition: selection
falsepositives:
    - Legitimate administration
level: medium

```
