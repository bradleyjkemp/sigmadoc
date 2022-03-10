---
title: "Invoke-Obfuscation CLIP+ Launcher"
aliases:
  - "/rule/f7385ee2-0e0c-11eb-adc1-0242ac120002"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_invoke_obfuscation_clip_services.yml))
```yaml
title: Invoke-Obfuscation CLIP+ Launcher
id: f7385ee2-0e0c-11eb-adc1-0242ac120002
description: Detects Obfuscated use of Clip.exe to execute PowerShell
status: experimental
author: Jonathan Cheong, oscd.community
date: 2020/10/13
modified: 2022/02/03
references:
     - https://github.com/Neo23x0/sigma/issues/1009 #(Task 26)
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
        ImagePath|contains|all: 
            - 'cmd'
            - 'clip'
            - 'clipboard]::'
    condition: selection
falsepositives:
    - Unknown
level: high
```
