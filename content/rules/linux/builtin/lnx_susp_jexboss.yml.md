---
title: "JexBoss Command Sequence"
aliases:
  - "/rule/8ec2c8b4-557a-4121-b87c-5dfb3a602fae"
ruleid: 8ec2c8b4-557a-4121-b87c-5dfb3a602fae

tags:
  - attack.execution
  - attack.t1059.004



status: test





date: Thu, 8 Nov 2018 23:21:21 +0100


---

Detects suspicious command sequence that JexBoss

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.us-cert.gov/ncas/analysis-reports/AR18-312A


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/builtin/lnx_susp_jexboss.yml))
```yaml
title: JexBoss Command Sequence
id: 8ec2c8b4-557a-4121-b87c-5dfb3a602fae
status: test
description: Detects suspicious command sequence that JexBoss
author: Florian Roth
references:
  - https://www.us-cert.gov/ncas/analysis-reports/AR18-312A
date: 2017/08/24
modified: 2021/11/27
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
