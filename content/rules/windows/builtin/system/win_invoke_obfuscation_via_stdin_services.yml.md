---
title: "Invoke-Obfuscation Via Stdin"
aliases:
  - "/rule/487c7524-f892-4054-b263-8a0ace63fc25"
ruleid: 487c7524-f892-4054-b263-8a0ace63fc25

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via Stdin in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/system/win_invoke_obfuscation_via_stdin_services.yml))
```yaml
title: Invoke-Obfuscation Via Stdin
id: 487c7524-f892-4054-b263-8a0ace63fc25
description: Detects Obfuscated Powershell via Stdin in Scripts
status: experimental
author: Nikita Nazarov, oscd.community
date: 2020/10/12
modified: 2021/11/30
references:
    - https://github.com/Neo23x0/sigma/issues/1009 #(Task28)
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
        ImagePath|re: '(?i).*(set).*&&\s?set.*(environment|invoke|\${?input).*&&.*"'
    condition: selection
falsepositives:
    - Unknown
level: high
```
