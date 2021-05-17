---
title: "Ps.exe Renamed SysInternals Tool"
aliases:
  - "/rule/18da1007-3f26-470f-875d-f77faf1cab31"

tags:
  - attack.defense_evasion
  - attack.g0035
  - attack.t1036
  - attack.t1036.003
  - car.2013-05-009





level: high



date: Sun, 22 Oct 2017 12:55:06 +0200


---

Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report

<!--more-->


## Known false-positives

* Renamed SysInternals tool



## References

* https://www.us-cert.gov/ncas/alerts/TA17-293A


## Raw rule
```yaml
title: Ps.exe Renamed SysInternals Tool
id: 18da1007-3f26-470f-875d-f77faf1cab31
description: Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report
references:
    - https://www.us-cert.gov/ncas/alerts/TA17-293A
tags:
    - attack.defense_evasion
    - attack.g0035
    - attack.t1036 # an old one
    - attack.t1036.003
    - car.2013-05-009
author: Florian Roth
date: 2017/10/22
modified: 2020/08/27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'ps.exe -accepteula'
    condition: selection
falsepositives:
    - Renamed SysInternals tool
level: high
```
