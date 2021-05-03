---
title: "Mimikatz Use"
aliases:
  - "/rule/06d71506-7beb-4f22-8888-e2e5e2ca7fd8"

tags:
  - attack.s0002
  - attack.t1003
  - attack.lateral_movement
  - attack.credential_access
  - car.2013-07-001
  - car.2019-04-004
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.001
  - attack.t1003.006



date: Tue, 27 Dec 2016 14:49:54 +0100


---

This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)

<!--more-->


## Known false-positives

* Naughty administrators
* Penetration test




## Raw rule
```yaml
title: Mimikatz Use
id: 06d71506-7beb-4f22-8888-e2e5e2ca7fd8
description: This method detects mimikatz keywords in different Eventlogs (some of them only appear in older Mimikatz version that are however still used by different threat groups)
author: Florian Roth
date: 2017/01/10
modified: 2019/10/11
tags:
    - attack.s0002
    - attack.t1003          # an old one
    - attack.lateral_movement
    - attack.credential_access
    - car.2013-07-001
    - car.2019-04-004
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.001
    - attack.t1003.006
logsource:
    product: windows
detection:
    keywords:
        Message:
            - "* mimikatz *"
            - "* mimilib *"
            - "* <3 eo.oe *"
            - "* eo.oe.kiwi *"
            - "* privilege::debug *"
            - "* sekurlsa::logonpasswords *"
            - "* lsadump::sam *"
            - "* mimidrv.sys *"
            - "* p::d *"
            - "* s::l *"
    condition: keywords
falsepositives:
    - Naughty administrators
    - Penetration test
level: critical

```