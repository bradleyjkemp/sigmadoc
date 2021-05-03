---
title: "CobaltStrike Process Injection"
aliases:
  - "/rule/6309645e-122d-4c5b-bb2b-22e4f9c2fa42"

tags:
  - attack.defense_evasion
  - attack.t1055
  - attack.t1055.001



date: Fri, 30 Nov 2018 10:25:05 +0100


---

Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons

<!--more-->


## Known false-positives

* unknown



## References

* https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f
* https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/


## Raw rule
```yaml
title: CobaltStrike Process Injection
id: 6309645e-122d-4c5b-bb2b-22e4f9c2fa42
description: Detects a possible remote threat creation with certain characteristics which are typical for Cobalt Strike beacons
references:
    - https://medium.com/@olafhartong/cobalt-strike-remote-threads-detection-206372d11d0f
    - https://blog.cobaltstrike.com/2018/04/09/cobalt-strike-3-11-the-snake-that-eats-its-tail/
tags:
    - attack.defense_evasion
    - attack.t1055          # an old one
    - attack.t1055.001
status: experimental
author: Olaf Hartong, Florian Roth, Aleksey Potapov, oscd.community
date: 2018/11/30
modified: 2020/08/28
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 8
        TargetProcessAddress|endswith: 
            - '0B80'
            - '0C7C'
            - '0C88'
    condition: selection
falsepositives:
    - unknown
level: high


```