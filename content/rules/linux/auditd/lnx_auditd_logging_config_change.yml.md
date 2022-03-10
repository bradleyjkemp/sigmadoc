---
title: "Logging Configuration Changes on Linux Host"
aliases:
  - "/rule/c830f15d-6f6e-430f-8074-6f73d6807841"


tags:
  - attack.defense_evasion
  - attack.t1562.006



status: test





date: Fri, 25 Oct 2019 17:57:56 +0300


---

Detect changes of syslog daemons configuration files

<!--more-->


## Known false-positives

* Legitimate administrative activity



## References

* self experience


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/auditd/lnx_auditd_logging_config_change.yml))
```yaml
title: Logging Configuration Changes on Linux Host
id: c830f15d-6f6e-430f-8074-6f73d6807841
status: test
description: Detect changes of syslog daemons configuration files
author: Mikhail Larin, oscd.community
references:
  - self experience
date: 2019/10/25
modified: 2021/11/27
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
  - attack.t1562.006

```
