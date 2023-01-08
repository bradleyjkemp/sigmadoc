---
title: "ProcessHacker Privilege Elevation"
aliases:
  - "/rule/c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9"
ruleid: c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9

tags:
  - attack.execution
  - attack.privilege_escalation
  - attack.t1543.003
  - attack.t1569.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a ProcessHacker tool that elevated privileges to a very high level

<!--more-->


## Known false-positives

* Unlikely



## References

* https://twitter.com/1kwpeter/status/1397816101455765504


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_susp_proceshacker.yml))
```yaml
title: ProcessHacker Privilege Elevation
id: c4ff1eac-84ad-44dd-a6fb-d56a92fc43a9
description: Detects a ProcessHacker tool that elevated privileges to a very high level
status: experimental
references:
    - https://twitter.com/1kwpeter/status/1397816101455765504
author: Florian Roth
date: 2021/05/27
modified: 2021/11/30
tags:
    - attack.execution
    - attack.privilege_escalation
    - attack.t1543.003
    - attack.t1569.002
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ServiceName|startswith: 'ProcessHacker'
        AccountName: 'LocalSystem'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
