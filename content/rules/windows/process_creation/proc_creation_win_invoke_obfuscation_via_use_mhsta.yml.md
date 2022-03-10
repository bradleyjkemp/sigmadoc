---
title: "Invoke-Obfuscation Via Use MSHTA"
aliases:
  - "/rule/ac20ae82-8758-4f38-958e-b44a3140ca88"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via use MSHTA in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_use_mhsta.yml))
```yaml
title: Invoke-Obfuscation Via Use MSHTA
id: ac20ae82-8758-4f38-958e-b44a3140ca88
status: test
description: Detects Obfuscated Powershell via use MSHTA in Scripts
author: Nikita Nazarov, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009   #(Task31)
date: 2020/10/08
modified: 2022/03/08
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'set'
      - '&&'
      - 'mshta'
      - 'vbscript:createobject'
      - '.run'
      - '(window.close)'
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
