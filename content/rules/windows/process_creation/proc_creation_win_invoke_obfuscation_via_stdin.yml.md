---
title: "Invoke-Obfuscation Via Stdin"
aliases:
  - "/rule/9c14c9fa-1a63-4a64-8e57-d19280559490"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via Stdin in Scripts

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_stdin.yml))
```yaml
title: Invoke-Obfuscation Via Stdin
id: 9c14c9fa-1a63-4a64-8e57-d19280559490
status: test
description: Detects Obfuscated Powershell via Stdin in Scripts
author: Nikita Nazarov, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009   #(Task28)
date: 2020/10/12
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re: '(?i).*(set).*&&\s?set.*(environment|invoke|\${?input).*&&.*"'
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
