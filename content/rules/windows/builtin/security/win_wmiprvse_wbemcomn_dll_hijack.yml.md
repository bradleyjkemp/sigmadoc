---
title: "T1047 Wmiprvse Wbemcomn DLL Hijack"
aliases:
  - "/rule/f6c68d5f-e101-4b86-8c84-7d96851fd65c"


tags:
  - attack.execution
  - attack.t1047
  - attack.lateral_movement
  - attack.t1021.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network for a WMI DLL Hijack scenario.

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/08_lateral_movement/WIN-201009173318.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_wmiprvse_wbemcomn_dll_hijack.yml))
```yaml
title: T1047 Wmiprvse Wbemcomn DLL Hijack
id: f6c68d5f-e101-4b86-8c84-7d96851fd65c
status: test
description: Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network for a WMI DLL Hijack scenario.
author: Roberto Rodriguez @Cyb3rWard0g, Open Threat Research (OTR)
references:
  - https://threathunterplaybook.com/notebooks/windows/08_lateral_movement/WIN-201009173318.html
date: 2020/10/12
modified: 2022/02/24
logsource:
  product: windows
  service: security
detection:
  selection:
    Provider_Name: Microsoft-Windows-Security-Auditing
    EventID: 5145
    RelativeTargetName|endswith: '\wbem\wbemcomn.dll'
  filter:
    SubjectUserName|endswith: '$'
  condition: selection and not filter
falsepositives:
  - Unknown
level: critical
tags:
  - attack.execution
  - attack.t1047
  - attack.lateral_movement
  - attack.t1021.002

```
