---
title: "Invoke-Obfuscation Via Stdin"
aliases:
  - "/rule/86b896ba-ffa1-4fea-83e3-ee28a4c915c7"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via Stdin in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_stdin.yml))
```yaml
title: Invoke-Obfuscation Via Stdin
id: 86b896ba-ffa1-4fea-83e3-ee28a4c915c7
description: Detects Obfuscated Powershell via Stdin in Scripts
status: experimental
author: Nikita Nazarov, oscd.community
date: 2020/10/12
modified: 2021/10/16
references:
     - https://github.com/Neo23x0/sigma/issues/1009 #(Task28)
tags:
    - attack.defense_evasion
    - attack.t1027
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection_4104:
        ScriptBlockText|re: '(?i).*(set).*&&\s?set.*(environment|invoke|\${?input).*&&.*"'
    condition: selection_4104
falsepositives:
    - Unknown
level: high

```
