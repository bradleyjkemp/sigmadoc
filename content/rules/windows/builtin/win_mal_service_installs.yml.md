---
title: "Malicious Service Installations"
aliases:
  - "/rule/5a105d34-05fc-401e-8553-272b45c1522d"

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1003
  - attack.t1035
  - attack.t1050
  - car.2013-09-005
  - attack.t1543.003
  - attack.t1569.002



date: Sun, 16 Feb 2020 23:24:00 +0100


---

Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity

<!--more-->


## Known false-positives

* Penetration testing




## Raw rule
```yaml
title: Malicious Service Installations
id: 5a105d34-05fc-401e-8553-272b45c1522d
description: Detects known malicious service installs that only appear in cases of lateral movement, credential dumping and other suspicious activity
author: Florian Roth, Daniil Yugoslavskiy, oscd.community (update)
date: 2017/03/27
modified: 2019/11/01
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1003
    - attack.t1035          # an old one
    - attack.t1050          # an old one
    - car.2013-09-005
    - attack.t1543.003
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
    malsvc_paexec:
        ServiceFileName|contains: '\PAExec'
    malsvc_wannacry:
        ServiceName: 'mssecsvc2.0'
    malsvc_persistence:
        ServiceFileName|contains: 'net user'
    condition: selection and 1 of malsvc_*
falsepositives:
    - Penetration testing
level: critical

```