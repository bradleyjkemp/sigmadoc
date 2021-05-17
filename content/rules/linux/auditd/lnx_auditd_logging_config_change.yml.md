---
title: "Logging Configuration Changes on Linux Host"
aliases:
  - "/rule/c830f15d-6f6e-430f-8074-6f73d6807841"

tags:
  - attack.defense_evasion
  - attack.t1054
  - attack.t1562.006



status: experimental



level: high



date: Fri, 25 Oct 2019 17:57:56 +0300


---

Detect changes of syslog daemons configuration files

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* self experience


## Raw rule
```yaml
title: Logging Configuration Changes on Linux Host
id: c830f15d-6f6e-430f-8074-6f73d6807841
status: experimental
description: Detect changes of syslog daemons configuration files
    # Example config for this one (place it at the top of audit.rules)
    # -w /etc/syslog.conf -p wa -k etc_modify_syslogconfig
    # -w /etc/rsyslog.conf -p wa -k etc_modify_rsyslogconfig
    # -w /etc/syslog-ng/syslog-ng.conf -p wa -k etc_modify_syslogngconfig
author: Mikhail Larin, oscd.community
date: 2019/10/25
references:
    - self experience
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name:
            - /etc/syslog.conf
            - /etc/rsyslog.conf
            - /etc/syslog-ng/syslog-ng.conf
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
