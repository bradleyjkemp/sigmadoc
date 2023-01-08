---
title: "Invoke-Obfuscation Via Use Clip"
aliases:
  - "/rule/63e3365d-4824-42d8-8b82-e56810fefa0c"
ruleid: 63e3365d-4824-42d8-8b82-e56810fefa0c

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via use Clip.exe in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_invoke_obfuscation_via_use_clip_services.yml))
```yaml
title: Invoke-Obfuscation Via Use Clip
id: 63e3365d-4824-42d8-8b82-e56810fefa0c
description: Detects Obfuscated Powershell via use Clip.exe in Scripts
status: experimental
author: Nikita Nazarov, oscd.community
date: 2020/10/09
modified: 2021/11/30
references:
    - https://github.com/Neo23x0/sigma/issues/1009 #(Task29)
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|re: '(?i).*?echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?).*'
    condition: selection 
falsepositives:
    - Unknown
level: high
```
