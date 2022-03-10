---
title: "Execute Code with Pester.bat"
aliases:
  - "/rule/59e938ff-0d6d-4dc3-b13f-36cc28734d4e"


tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1216



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)

<!--more-->


## Known false-positives

* Legitimate use of Pester for writing tests for Powershell scripts and modules



## References

* https://twitter.com/Oddvarmoe/status/993383596244258816


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_pester.yml))
```yaml
title: Execute Code with Pester.bat
id: 59e938ff-0d6d-4dc3-b13f-36cc28734d4e
status: test
description: Detects code execution via Pester.bat (Pester - Powershell Modulte for testing)
author: Julia Fomina, oscd.community
references:
  - https://twitter.com/Oddvarmoe/status/993383596244258816
date: 2020/10/08
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  powershell_module:
    Image|endswith: '\powershell.exe'
    CommandLine|contains|all:
      - 'Pester'
      - 'Get-Help'
  cmd_execution:
    Image|endswith: '\cmd.exe'
    CommandLine|contains|all:
      - 'pester'
      - ';'
  get_help:
    CommandLine|contains:
      - 'help'
      - '?'
  condition: powershell_module or (cmd_execution and get_help)
falsepositives:
  - Legitimate use of Pester for writing tests for Powershell scripts and modules
level: medium
tags:
  - attack.execution
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1216

```
