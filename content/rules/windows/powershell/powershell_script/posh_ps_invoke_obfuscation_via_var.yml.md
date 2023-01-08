---
title: "Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION"
aliases:
  - "/rule/e54f5149-6ba3-49cf-b153-070d24679126"
ruleid: e54f5149-6ba3-49cf-b153-070d24679126

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via VAR++ LAUNCHER

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_var.yml))
```yaml
title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION
id: e54f5149-6ba3-49cf-b153-070d24679126
description: Detects Obfuscated Powershell via VAR++ LAUNCHER
status: experimental
author: Timur Zinniatullin, oscd.community
date: 2020/10/13
modified: 2021/10/16
references:
    - https://github.com/Neo23x0/sigma/issues/1009 #(Task27)
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
        ScriptBlockText|re: '(?i).*&&set.*(\{\d\}){2,}\\\"\s+?\-f.*&&.*cmd.*\/c' # FPs with |\/r
    condition: selection_4104
falsepositives:
    - Unknown
level: high

```
