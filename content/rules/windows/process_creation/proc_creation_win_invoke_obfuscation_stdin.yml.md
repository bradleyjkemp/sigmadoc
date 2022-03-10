---
title: "Invoke-Obfuscation STDIN+ Launcher"
aliases:
  - "/rule/6c96fc76-0eb1-11eb-adc1-0242ac120002"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated use of stdin to execute PowerShell

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_stdin.yml))
```yaml
title: Invoke-Obfuscation STDIN+ Launcher
id: 6c96fc76-0eb1-11eb-adc1-0242ac120002
status: test
description: Detects Obfuscated use of stdin to execute PowerShell
author: Jonathan Cheong, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009    #(Task 25)
date: 2020/10/15
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re: '.*cmd.{0,5}(?:\/c|\/r).+powershell.+(?:\$\{?input\}?|noexit).+\"'
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
