---
title: "Exfiltration and Tunneling Tools Execution"
aliases:
  - "/rule/c75309a3-59f8-4a8d-9c2c-4c927ad50555"

tags:
  - attack.exfiltration
  - attack.command_and_control
  - attack.t1043
  - attack.t1041
  - attack.t1572
  - attack.t1071.001



date: Fri, 25 Oct 2019 04:30:55 +0200


---

Execution of well known tools for data exfiltration and tunneling

<!--more-->


## Known false-positives

* Legitimate Administrator using tools




## Raw rule
```yaml
title: Exfiltration and Tunneling Tools Execution
id: c75309a3-59f8-4a8d-9c2c-4c927ad50555
description: Execution of well known tools for data exfiltration and tunneling
status: experimental
author: Daniil Yugoslavskiy, oscd.community
date: 2019/10/24
modified: 2020/08/29
tags:
    - attack.exfiltration
    - attack.command_and_control
    - attack.t1043   # an old one
    - attack.t1041
    - attack.t1572
    - attack.t1071.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\plink.exe'
            - '\socat.exe'
            - '\stunnel.exe'
            - '\httptunnel.exe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tools
level: medium

```
