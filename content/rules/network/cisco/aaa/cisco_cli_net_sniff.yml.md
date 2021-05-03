---
title: "Cisco Sniffing"
aliases:
  - "/rule/b9e1f193-d236-4451-aaae-2f3d2102120d"

tags:
  - attack.credential_access
  - attack.discovery
  - attack.t1040



date: Thu, 14 Nov 2019 20:55:28 +0100


---

Show when a monitor or a span/rspan is setup or modified

<!--more-->


## Known false-positives

* Admins may setup new or modify old spans, or use a monitor for troubleshooting




## Raw rule
```yaml
title: Cisco Sniffing
id: b9e1f193-d236-4451-aaae-2f3d2102120d
status: experimental
description: Show when a monitor or a span/rspan is setup or modified
author: Austin Clark
date: 2019/08/11
logsource:
    product: cisco
    service: aaa
    category: accounting
fields:
    - CmdSet
detection:
    keywords:
        - 'monitor capture point'
        - 'set span'
        - 'set rspan'
    condition: keywords
falsepositives:
    - Admins may setup new or modify old spans, or use a monitor for troubleshooting
level: medium
tags:
    - attack.credential_access
    - attack.discovery
    - attack.t1040
```
