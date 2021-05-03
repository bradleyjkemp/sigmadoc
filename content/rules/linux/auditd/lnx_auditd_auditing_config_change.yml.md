---
title: "Auditing Configuration Changes on Linux Host"
aliases:
  - "/rule/977ef627-4539-4875-adf4-ed8f780c4922"

tags:
  - attack.defense_evasion
  - attack.t1054
  - attack.t1562.006



date: Fri, 25 Oct 2019 17:57:56 +0300


---

Detect changes in auditd configuration files

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* https://github.com/Neo23x0/auditd/blob/master/audit.rules
* self experience


## Raw rule
```yaml
title: Auditing Configuration Changes on Linux Host
id: 977ef627-4539-4875-adf4-ed8f780c4922
status: experimental
description: Detect changes in auditd configuration files
    # Example config for this one (place it at the top of audit.rules)
    # -w /etc/audit/ -p wa -k etc_modify_auditconfig
    # -w /etc/libaudit.conf -p wa -k etc_modify_libauditconfig
    # -w /etc/audisp/ -p wa -k etc_modify_audispconfig
author: Mikhail Larin, oscd.community
date: 2019/10/25
references:
    - https://github.com/Neo23x0/auditd/blob/master/audit.rules
    - self experience
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
    - attack.t1054    # an old one
    - attack.t1562.006
```
