---
title: "Suspicious TSCON Start"
aliases:
  - "/rule/9847f263-4a81-424f-970c-875dab15b79b"

tags:
  - attack.command_and_control
  - attack.t1219



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a tscon.exe start as LOCAL SYSTEM

<!--more-->


## Known false-positives

* Unknown



## References

* http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
* https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6


## Raw rule
```yaml
title: Suspicious TSCON Start
id: 9847f263-4a81-424f-970c-875dab15b79b
status: experimental
description: Detects a tscon.exe start as LOCAL SYSTEM
references:
    - http://www.korznikov.com/2017/03/0-day-or-feature-privilege-escalation.html
    - https://medium.com/@networksecurity/rdp-hijacking-how-to-hijack-rds-and-remoteapp-sessions-transparently-to-move-through-an-da2a1e73a5f6
author: Florian Roth
date: 2018/03/17
tags:
    - attack.command_and_control
    - attack.t1219
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: NT AUTHORITY\SYSTEM
        Image: '*\tscon.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```