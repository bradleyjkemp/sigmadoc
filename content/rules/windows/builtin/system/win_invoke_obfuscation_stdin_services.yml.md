---
title: "Invoke-Obfuscation STDIN+ Launcher"
aliases:
  - "/rule/72862bf2-0eb1-11eb-adc1-0242ac120002"
ruleid: 72862bf2-0eb1-11eb-adc1-0242ac120002

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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_invoke_obfuscation_stdin_services.yml))
```yaml
title: Invoke-Obfuscation STDIN+ Launcher
id: 72862bf2-0eb1-11eb-adc1-0242ac120002
description: Detects Obfuscated use of stdin to execute PowerShell
status: experimental
author: Jonathan Cheong, oscd.community
date: 2020/10/15
modified: 2021/11/30
references:
     - https://github.com/Neo23x0/sigma/issues/1009 #(Task 25)
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
        ImagePath|re: '.*cmd.{0,5}(?:\/c|\/r).+powershell.+(?:\$\{?input\}?|noexit).+\"'
    condition: selection 
falsepositives:
    - Unknown
level: high
```
