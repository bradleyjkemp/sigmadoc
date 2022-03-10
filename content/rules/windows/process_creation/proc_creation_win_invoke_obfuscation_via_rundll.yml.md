---
title: "Invoke-Obfuscation RUNDLL LAUNCHER"
aliases:
  - "/rule/056a7ee1-4853-4e67-86a0-3fd9ceed7555"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via RUNDLL LAUNCHER

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_rundll.yml))
```yaml
title: Invoke-Obfuscation RUNDLL LAUNCHER
id: 056a7ee1-4853-4e67-86a0-3fd9ceed7555
status: test
description: Detects Obfuscated Powershell via RUNDLL LAUNCHER
author: Timur Zinniatullin, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009   #(Task 23)
date: 2020/10/18
modified: 2022/03/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'rundll32.exe'
      - 'shell32.dll'
      - 'shellexec_rundll'
      - 'powershell'
  condition: selection
falsepositives:
  - Unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001

```
