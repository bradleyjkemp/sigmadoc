---
title: "Invoke-Obfuscation VAR+ Launcher"
aliases:
  - "/rule/27aec9c9-dbb0-4939-8422-1742242471d0"


tags:
  - attack.defense_evasion
  - attack.t1027
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Obfuscated use of Environment Variables to execute PowerShell

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/Neo23x0/sigma/issues/1009


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_invoke_obfuscation_var.yml))
```yaml
title: Invoke-Obfuscation VAR+ Launcher
id: 27aec9c9-dbb0-4939-8422-1742242471d0
status: test
description: Detects Obfuscated use of Environment Variables to execute PowerShell
author: Jonathan Cheong, oscd.community
references:
  - https://github.com/Neo23x0/sigma/issues/1009    #(Task 24)
date: 2020/10/15
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|re: '.*cmd.{0,5}(?:\/c|\/r)(?:\s|)\"set\s[a-zA-Z]{3,6}.*(?:\{\d\}){1,}\\\"\s+?\-f(?:.*\)){1,}.*\"'
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
