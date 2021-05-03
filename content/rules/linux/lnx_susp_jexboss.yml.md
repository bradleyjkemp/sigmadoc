---
title: "JexBoss Command Sequence"
aliases:
  - "/rule/8ec2c8b4-557a-4121-b87c-5dfb3a602fae"

tags:
  - attack.execution
  - attack.t1059.004



date: Thu, 8 Nov 2018 23:21:21 +0100


---

Detects suspicious command sequence that JexBoss

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.us-cert.gov/ncas/analysis-reports/AR18-312A


## Raw rule
```yaml
title: JexBoss Command Sequence
id: 8ec2c8b4-557a-4121-b87c-5dfb3a602fae
description: Detects suspicious command sequence that JexBoss
author: Florian Roth
date: 2017/08/24
references:
    - https://www.us-cert.gov/ncas/analysis-reports/AR18-312A
logsource:
    product: linux
detection:
    selection1:
        - 'bash -c /bin/bash'
    selection2:
        - '&/dev/tcp/'
    condition: selection1 and selection2
falsepositives:
    - Unknown
level: high
tags:
    - attack.execution
    - attack.t1059.004
```
