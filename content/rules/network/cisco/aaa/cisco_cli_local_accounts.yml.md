---
title: "Cisco Local Accounts"
aliases:
  - "/rule/6d844f0f-1c18-41af-8f19-33e7654edfc3"

tags:
  - attack.persistence
  - attack.t1136
  - attack.t1136.001
  - attack.t1098



date: Thu, 14 Nov 2019 20:55:28 +0100


---

Find local accounts being created or modified as well as remote authentication configurations

<!--more-->


## Known false-positives

* When remote authentication is in place, this should not change often




## Raw rule
```yaml
title: Cisco Local Accounts
id: 6d844f0f-1c18-41af-8f19-33e7654edfc3
status: experimental
description: Find local accounts being created or modified as well as remote authentication configurations
author: Austin Clark
date: 2019/08/12
modified: 2020/09/02
logsource:
    product: cisco
    service: aaa
    category: accounting
fields:
    - CmdSet
detection:
    keywords:
        - 'username'
        - 'aaa'
    condition: keywords
falsepositives:
    - When remote authentication is in place, this should not change often
level: high
tags:
    - attack.persistence
    - attack.t1136          # an old one
    - attack.t1136.001
    - attack.t1098
```
