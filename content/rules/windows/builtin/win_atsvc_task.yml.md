---
title: "Remote Task Creation via ATSVC Named Pipe"
aliases:
  - "/rule/f6de6525-4509-495a-8a82-1f8b0ed73a00"

tags:
  - attack.lateral_movement
  - attack.persistence
  - attack.t1053
  - car.2013-05-004
  - car.2015-04-001
  - attack.t1053.002





level: medium



date: Wed, 3 Apr 2019 13:08:12 +0200


---

Detects remote task creation via at.exe or API interacting with ATSVC namedpipe

<!--more-->


## Known false-positives

* pentesting



## References

* https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html


## Raw rule
```yaml
title: Remote Task Creation via ATSVC Named Pipe
id: f6de6525-4509-495a-8a82-1f8b0ed73a00
description: Detects remote task creation via at.exe or API interacting with ATSVC namedpipe
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://blog.menasec.net/2019/03/threat-hunting-25-scheduled-tasks-for.html
tags:
    - attack.lateral_movement
    - attack.persistence
    - attack.t1053          # an old one
    - car.2013-05-004
    - car.2015-04-001
    - attack.t1053.002
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\IPC$
        RelativeTargetName: atsvc
        Accesses: '*WriteData*'
    condition: selection
falsepositives:
    - pentesting
level: medium

```
