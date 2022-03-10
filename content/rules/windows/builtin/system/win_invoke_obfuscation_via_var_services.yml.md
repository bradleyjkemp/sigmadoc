---
title: "Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION"
aliases:
  - "/rule/14bcba49-a428-42d9-b943-e2ce0f0f7ae6"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_invoke_obfuscation_via_var_services.yml))
```yaml
title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION
id: 14bcba49-a428-42d9-b943-e2ce0f0f7ae6
description: Detects Obfuscated Powershell via VAR++ LAUNCHER
status: experimental
author: Timur Zinniatullin, oscd.community
date: 2020/10/13
modified: 2021/11/30
references:
    - https://github.com/Neo23x0/sigma/issues/1009 #(Task27)
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
        ImagePath|re: '(?i).*&&set.*(\{\d\}){2,}\\\"\s+?\-f.*&&.*cmd.*\/c' # FPs with |\/r
    condition: selection
falsepositives:
    - Unknown
level: high
```
