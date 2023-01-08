---
title: "Ps.exe Renamed SysInternals Tool"
aliases:
  - "/rule/18da1007-3f26-470f-875d-f77faf1cab31"
ruleid: 18da1007-3f26-470f-875d-f77faf1cab31

tags:
  - attack.defense_evasion
  - attack.g0035
  - attack.t1036.003
  - car.2013-05-009



status: test





date: Sun, 22 Oct 2017 12:55:06 +0200


---

Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report

<!--more-->


## Known false-positives

* Renamed SysInternals tool



## References

* https://www.us-cert.gov/ncas/alerts/TA17-293A


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_ta17_293a_ps.yml))
```yaml
title: Ps.exe Renamed SysInternals Tool
id: 18da1007-3f26-470f-875d-f77faf1cab31
status: test
description: Detects renamed SysInternals tool execution with a binary named ps.exe as used by Dragonfly APT group and documented in TA17-293A report
author: Florian Roth
references:
  - https://www.us-cert.gov/ncas/alerts/TA17-293A
date: 2017/10/22
modified: 2021/11/27
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
tags:
  - attack.defense_evasion
  - attack.g0035
  - attack.t1036.003
  - car.2013-05-009

```
