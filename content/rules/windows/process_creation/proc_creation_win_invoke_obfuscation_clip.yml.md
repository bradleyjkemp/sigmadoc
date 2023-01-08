---
title: "Invoke-Obfuscation CLIP+ Launcher"
aliases:
  - "/rule/b222df08-0e07-11eb-adc1-0242ac120002"
ruleid: b222df08-0e07-11eb-adc1-0242ac120002

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated use of Clip.exe to execute PowerShell

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_clip.yml))
```yaml
title: Invoke-Obfuscation CLIP+ Launcher
id: b222df08-0e07-11eb-adc1-0242ac120002
status: test
description: Detects Obfuscated use of Clip.exe to execute PowerShell
author: Jonathan Cheong, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009    #(Task 26)
date: 2020/10/13
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re: '.*cmd.{0,5}(?:\/c|\/r).+clip(?:\.exe)?.{0,4}&&.+clipboard]::\(\s\\\"\{\d\}.+\-f.+\"'
  condition: selection
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001

```
