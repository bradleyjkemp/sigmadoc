---
title: "Invoke-Obfuscation VAR+ Launcher"
aliases:
  - "/rule/8ca7004b-e620-4ecb-870e-86129b5b8e75"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated use of Environment Variables to execute PowerShell

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_invoke_obfuscation_var_services.yml))
```yaml
title: Invoke-Obfuscation VAR+ Launcher
id: 8ca7004b-e620-4ecb-870e-86129b5b8e75
description: Detects Obfuscated use of Environment Variables to execute PowerShell
status: experimental
author: Jonathan Cheong, oscd.community
date: 2020/10/15
modified: 2021/11/30
references:
     - https://github.com/Neo23x0/sigma/issues/1009 #(Task 24)
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
        ImagePath|re: '.*cmd.{0,5}(?:\/c|\/r)(?:\s|)\"set\s[a-zA-Z]{3,6}.*(?:\{\d\}){1,}\\\"\s+?\-f(?:.*\)){1,}.*\"'
    condition: selection
falsepositives:
    - Unknown
level: high
```
