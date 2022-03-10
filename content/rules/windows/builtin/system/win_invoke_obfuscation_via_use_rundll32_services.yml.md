---
title: "Invoke-Obfuscation Via Use Rundll32"
aliases:
  - "/rule/641a4bfb-c017-44f7-800c-2aee0184ce9b"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via use Rundll32 in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_invoke_obfuscation_via_use_rundll32_services.yml))
```yaml
title: Invoke-Obfuscation Via Use Rundll32
id: 641a4bfb-c017-44f7-800c-2aee0184ce9b
description: Detects Obfuscated Powershell via use Rundll32 in Scripts
status: experimental
author: Nikita Nazarov, oscd.community
date: 2020/10/09
modified: 2022/03/07
references:
    - https://github.com/Neo23x0/sigma/issues/1009 #(Task30)
logsource:
    product: windows
    service: system
detection:
    selection:
        Provider_Name: 'Service Control Manager'
        EventID: 7045
        ImagePath|contains|all:
            - '&&'
            - 'rundll32'
            - 'shell32.dll'
            - 'shellexec_rundll'
        ImagePath|contains:    
            - 'value'
            - 'invoke'
            - 'comspec'
            - 'iex'
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
