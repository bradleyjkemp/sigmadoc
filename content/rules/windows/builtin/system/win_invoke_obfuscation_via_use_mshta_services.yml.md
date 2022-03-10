---
title: "Invoke-Obfuscation Via Use MSHTA"
aliases:
  - "/rule/7e9c7999-0f9b-4d4a-a6ed-af6d553d4af4"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via use MSHTA in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_invoke_obfuscation_via_use_mshta_services.yml))
```yaml
title: Invoke-Obfuscation Via Use MSHTA
id: 7e9c7999-0f9b-4d4a-a6ed-af6d553d4af4
description: Detects Obfuscated Powershell via use MSHTA in Scripts
status: experimental
author: Nikita Nazarov, oscd.community
date: 2020/10/09
modified: 2022/03/06
references:
    - https://github.com/Neo23x0/sigma/issues/1009 #(Task31)
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
        ImagePath|contains|all:
            - 'set'
            - '&&'
            - 'mshta'
            - 'vbscript:createobject'
            - '.run'
            - '(window.close)'
    condition: selection
falsepositives:
    - Unknown
level: high

```
