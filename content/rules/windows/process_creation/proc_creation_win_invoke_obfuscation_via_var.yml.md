---
title: "Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION"
aliases:
  - "/rule/e9f55347-2928-4c06-88e5-1a7f8169942e"
ruleid: e9f55347-2928-4c06-88e5-1a7f8169942e

tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated Powershell via VAR++ LAUNCHER

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_via_var.yml))
```yaml
title: Invoke-Obfuscation VAR++ LAUNCHER OBFUSCATION
id: e9f55347-2928-4c06-88e5-1a7f8169942e
status: test
description: Detects Obfuscated Powershell via VAR++ LAUNCHER
author: Timur Zinniatullin, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009   #(Task27)
date: 2020/10/13
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re: '(?i).*&&set.*(\{\d\}){2,}\\\"\s+?\-f.*&&.*cmd.*\/c'     # FPs with |\/r
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
