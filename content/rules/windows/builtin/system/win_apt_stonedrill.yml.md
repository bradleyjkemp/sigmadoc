---
title: "StoneDrill Service Install"
aliases:
  - "/rule/9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6"
ruleid: 9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6

tags:
  - attack.persistence
  - attack.g0064
  - attack.t1543.003



status: test





date: Tue, 7 Mar 2017 09:24:06 +0100


---

This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky

<!--more-->


## Known false-positives

* Unlikely



## References

* https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_apt_stonedrill.yml))
```yaml
title: StoneDrill Service Install
id: 9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6
status: test
description: This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky
author: Florian Roth
references:
  - https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/
date: 2017/03/07
modified: 2021/11/30
logsource:
  product: windows
  service: system
detection:
  selection:
    Provider_Name: 'Service Control Manager'
    EventID: 7045
    ServiceName: NtsSrv
    ServiceFileName|endswith: ' LocalService'
  condition: selection
falsepositives:
  - Unlikely
level: high
tags:
  - attack.persistence
  - attack.g0064
  - attack.t1543.003

```
