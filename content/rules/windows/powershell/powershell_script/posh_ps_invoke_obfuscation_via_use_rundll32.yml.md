---
title: "Invoke-Obfuscation Via Use Rundll32"
aliases:
  - "/rule/a5a30a6e-75ca-4233-8b8c-42e0f2037d3b"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via use Rundll32 in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_rundll32.yml))
```yaml
title: Invoke-Obfuscation Via Use Rundll32
id: a5a30a6e-75ca-4233-8b8c-42e0f2037d3b
description: Detects Obfuscated Powershell via use Rundll32 in Scripts
status: experimental
author: Nikita Nazarov, oscd.community
date: 2019/10/08
modified: 2022/03/08
references:
    - https://github.com/Neo23x0/sigma/issues/1009
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_4104:
        ScriptBlockText|contains|all:
            - '&&'
            - 'rundll32'
            - 'shell32.dll'
            - 'shellexec_rundll'
        ScriptBlockText|contains:
            - 'value'
            - 'invoke'
            - 'comspec'
            - 'iex'
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
