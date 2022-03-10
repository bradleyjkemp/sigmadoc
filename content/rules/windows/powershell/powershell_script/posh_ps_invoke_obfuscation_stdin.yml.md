---
title: "Invoke-Obfuscation STDIN+ Launcher"
aliases:
  - "/rule/779c8c12-0eb1-11eb-adc1-0242ac120002"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated use of stdin to execute PowerShell

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_stdin.yml))
```yaml
title: Invoke-Obfuscation STDIN+ Launcher
id: 779c8c12-0eb1-11eb-adc1-0242ac120002
description: Detects Obfuscated use of stdin to execute PowerShell
status: experimental
author: Jonathan Cheong, oscd.community
date: 2020/10/15
modified: 2021/10/16
references:
     - https://github.com/Neo23x0/sigma/issues/1009 #(Task 25)
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
        ScriptBlockText|re: '.*cmd.{0,5}(?:\/c|\/r).+powershell.+(?:\$\{?input\}?|noexit).+\"'
    condition: selection_4104
falsepositives:
    - Unknown
level: high
```
