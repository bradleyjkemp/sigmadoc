---
title: "Suspicious RDP Redirect Using TSCON"
aliases:
  - "/rule/f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb"

tags:
  - attack.lateral_movement
  - attack.t1563.002
  - attack.t1076
  - car.2013-07-002



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious RDP session redirect using tscon.exe

<!--more-->


## Known false-positives

* Unknown



## References

* http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6


## Raw rule
```yaml
title: Suspicious RDP Redirect Using TSCON
id: f72aa3e8-49f9-4c7d-bd74-f8ab84ff9bbb
status: experimental
description: Detects a suspicious RDP session redirect using tscon.exe
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
tags:
    - attack.lateral_movement
    - attack.t1563.002
    - attack.t1076      # an old one
    - car.2013-07-002
author: Florian Roth
date: 2018/03/17
modified: 2020/08/29
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '* /dest:rdp-tcp:*'
    condition: selection
falsepositives:
    - Unknown
level: high

```
