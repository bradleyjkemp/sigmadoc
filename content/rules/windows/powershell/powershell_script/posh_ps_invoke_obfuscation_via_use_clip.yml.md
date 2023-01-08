---
title: "Invoke-Obfuscation Via Use Clip"
aliases:
  - "/rule/db92dd33-a3ad-49cf-8c2c-608c3e30ace0"
ruleid: db92dd33-a3ad-49cf-8c2c-608c3e30ace0

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via use Clip.exe in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_invoke_obfuscation_via_use_clip.yml))
```yaml
title: Invoke-Obfuscation Via Use Clip
id: db92dd33-a3ad-49cf-8c2c-608c3e30ace0
description: Detects Obfuscated Powershell via use Clip.exe in Scripts
status: experimental
author: Nikita Nazarov, oscd.community
date: 2020/10/09
modified: 2021/10/16
references:
     - https://github.com/Neo23x0/sigma/issues/1009 #(Task29)
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
        ScriptBlockText|re: '(?i).*?echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?).*'
    condition: selection_4104
falsepositives:
    - Unknown
level: high

```
