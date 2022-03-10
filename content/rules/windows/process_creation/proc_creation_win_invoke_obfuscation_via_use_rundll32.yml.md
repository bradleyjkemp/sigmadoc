---
title: "Invoke-Obfuscation Via Use Rundll32"
aliases:
  - "/rule/36c5146c-d127-4f85-8e21-01bf62355d5a"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via use Rundll32 in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_use_rundll32.yml))
```yaml
title: Invoke-Obfuscation Via Use Rundll32
id: 36c5146c-d127-4f85-8e21-01bf62355d5a
status: test
description: Detects Obfuscated Powershell via use Rundll32 in Scripts
author: Nikita Nazarov, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009
date: 2019/10/08
modified: 2022/03/08
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - '&&'
      - 'rundll32'
      - 'shell32.dll'
      - 'shellexec_rundll'
    CommandLine|contains:  
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
