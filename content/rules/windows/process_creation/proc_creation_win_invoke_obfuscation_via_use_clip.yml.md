---
title: "Invoke-Obfuscation Via Use Clip"
aliases:
  - "/rule/e1561947-b4e3-4a74-9bdd-83baed21bdb5"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via use Clip.exe in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_use_clip.yml))
```yaml
title: Invoke-Obfuscation Via Use Clip
id: e1561947-b4e3-4a74-9bdd-83baed21bdb5
status: test
description: Detects Obfuscated Powershell via use Clip.exe in Scripts
author: Nikita Nazarov, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009   #(Task29)
date: 2020/10/09
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re: '(?i).*?echo.*clip.*&&.*(Clipboard|i`?n`?v`?o`?k`?e`?).*'
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
