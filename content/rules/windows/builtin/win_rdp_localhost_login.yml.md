---
title: "RDP Login from Localhost"
aliases:
  - "/rule/51e33403-2a37-4d66-a574-1fda1782cc31"

tags:
  - attack.lateral_movement
  - attack.t1076
  - car.2013-07-002
  - attack.t1021.001



date: Mon, 28 Jan 2019 22:43:22 +0100


---

RDP login with localhost source address may be a tunnelled login

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html


## Raw rule
```yaml
title: RDP Login from Localhost
id: 51e33403-2a37-4d66-a574-1fda1782cc31
description: RDP login with localhost source address may be a tunnelled login
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/28
modified: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.t1076          # an old one
    - car.2013-07-002
    - attack.t1021.001
status: experimental
author: Thomas Patzke
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 10
        SourceNetworkAddress:
            - "::1"
            - "127.0.0.1"
    condition: selection
falsepositives:
    - Unknown
level: high

```