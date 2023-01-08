---
title: "Auditing Configuration Changes on Linux Host"
aliases:
  - "/rule/977ef627-4539-4875-adf4-ed8f780c4922"
ruleid: 977ef627-4539-4875-adf4-ed8f780c4922

tags:
  - attack.defense_evasion
  - attack.t1562.006



status: test





date: Fri, 25 Oct 2019 17:57:56 +0300


---

Detect changes in auditd configuration files

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* https://github.com/Neo23x0/auditd/blob/master/audit.rules
* self experience


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_auditing_config_change.yml))
```yaml
title: Auditing Configuration Changes on Linux Host
id: 977ef627-4539-4875-adf4-ed8f780c4922
status: test
description: Detect changes in auditd configuration files
author: Mikhail Larin, oscd.community
references:
  - https://github.com/Neo23x0/auditd/blob/master/audit.rules
  - self experience
date: 2019/10/25
modified: 2021/11/27
logsource:
  product: linux
  service: auditd
detection:
  selection:
    type: PATH
    name:
      - /etc/audit/*
      - /etc/libaudit.conf
      - /etc/audisp/*
  condition: selection
fields:
  - exe
  - comm
  - key
falsepositives:
  - Legitimate administrative activity
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.006

```
