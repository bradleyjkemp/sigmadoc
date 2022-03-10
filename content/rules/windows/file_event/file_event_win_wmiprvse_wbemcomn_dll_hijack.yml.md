---
title: "Wmiprvse Wbemcomn DLL Hijack"
aliases:
  - "/rule/614a7e17-5643-4d89-b6fe-f9df1a79641c"


tags:
  - attack.execution
  - attack.t1047
  - attack.lateral_movement
  - attack.t1021.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network and loading it for a WMI DLL Hijack scenario.

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/08_lateral_movement/WIN-201009173318.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_wmiprvse_wbemcomn_dll_hijack.yml))
```yaml
title: Wmiprvse Wbemcomn DLL Hijack
id: 614a7e17-5643-4d89-b6fe-f9df1a79641c
description: Detects a threat actor creating a file named `wbemcomn.dll` in the `C:\Windows\System32\wbem\` directory over the network and loading it for a WMI DLL Hijack scenario.
status: experimental
date: 2020/10/12
modified: 2021/09/09
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.execution
    - attack.t1047
    - attack.lateral_movement
    - attack.t1021.002
references:
    - https://threathunterplaybook.com/notebooks/windows/08_lateral_movement/WIN-201009173318.html
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image: System
        TargetFilename|endswith: '\wbem\wbemcomn.dll'
    condition: selection
falsepositives:
    - Unknown
level: critical
```
