---
title: "Invoke-Obfuscation CLIP+ Launcher"
aliases:
  - "/rule/73e67340-0d25-11eb-adc1-0242ac120002"
ruleid: 73e67340-0d25-11eb-adc1-0242ac120002

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated use of Clip.exe to execute PowerShell

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_clip.yml))
```yaml
title: Invoke-Obfuscation CLIP+ Launcher
id: 73e67340-0d25-11eb-adc1-0242ac120002
description: Detects Obfuscated use of Clip.exe to execute PowerShell
status: experimental
author: Jonathan Cheong, oscd.community
date: 2020/10/13
modified: 2021/10/16
references:
     - https://github.com/Neo23x0/sigma/issues/1009 #(Task 26)
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
        ScriptBlockText|re: '.*cmd.{0,5}(?:\/c|\/r).+clip(?:\.exe)?.{0,4}&&.+clipboard]::\(\s\\\"\{\d\}.+\-f.+\"'
    condition: selection_4104
falsepositives:
    - Unknown
level: high
```
