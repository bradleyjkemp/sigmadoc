---
title: "RDP over Reverse SSH Tunnel WFP"
aliases:
  - "/rule/5bed80b6-b3e8-428e-a3ae-d3c757589e41"

tags:
  - attack.defense_evasion
  - attack.command_and_control
  - attack.lateral_movement
  - attack.t1076
  - attack.t1090
  - attack.t1090.001
  - attack.t1090.002
  - attack.t1021.001
  - car.2013-07-002



date: Sat, 16 Feb 2019 19:36:01 +0100


---

Detects svchost hosting RDP termsvcs communicating with the loopback address

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/SBousseaden/status/1096148422984384514
* https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Command%20and%20Control/DE_RDP_Tunnel_5156.evtx


## Raw rule
```yaml
title: RDP over Reverse SSH Tunnel WFP
id: 5bed80b6-b3e8-428e-a3ae-d3c757589e41
status: experimental
description: Detects svchost hosting RDP termsvcs communicating with the loopback address
references:
    - https://twitter.com/SBousseaden/status/1096148422984384514
    - https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/blob/master/Command%20and%20Control/DE_RDP_Tunnel_5156.evtx
author: Samir Bousseaden
date: 2019/02/16
modified: 2020/08/23
tags:
    - attack.defense_evasion
    - attack.command_and_control
    - attack.lateral_movement
    - attack.t1076          # an old one
    - attack.t1090          # an old one
    - attack.t1090.001
    - attack.t1090.002
    - attack.t1021.001
    - car.2013-07-002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
    sourceRDP:
        SourcePort: 3389
        DestinationAddress:
            - '127.*'
            - '::1'
    destinationRDP:
        DestinationPort: 3389
        SourceAddress:
            - '127.*'
            - '::1'
    condition: selection and ( sourceRDP or destinationRDP )
falsepositives:
    - unknown
level: high

```
