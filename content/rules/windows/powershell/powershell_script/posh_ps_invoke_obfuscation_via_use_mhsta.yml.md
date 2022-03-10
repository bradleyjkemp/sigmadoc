---
title: "Invoke-Obfuscation Via Use MSHTA"
aliases:
  - "/rule/e55a5195-4724-480e-a77e-3ebe64bd3759"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_mhsta.yml))
```yaml
title: Invoke-Obfuscation Via Use MSHTA
id: e55a5195-4724-480e-a77e-3ebe64bd3759
description: Detects Obfuscated Powershell via use MSHTA in Scripts
status: experimental
author: Nikita Nazarov, oscd.community
date: 2020/10/08
modified: 2022/03/07
references:
    - https://github.com/Neo23x0/sigma/issues/1009 #(Task31)
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_4104:
        ScriptBlockText|contains|all:
            - 'set'
            - '&&'
            - 'mshta'
            - 'vbscript:createobject'
            - '.run'
            - '(window.close)'
    condition: selection_4104
falsepositives:
    - Unknown
level: high
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001

```
