---
title: "Run Once Task Execution as Configured in Registry"
aliases:
  - "/rule/198effb6-6c98-4d0c-9ea3-451fa143c45c"


tags:
  - attack.defense_evasion
  - attack.t1112



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

This rule detects the execution of Run Once task as configured in the registry

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/pabraeken/status/990717080805789697
* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Runonce.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_runonce_execution.yml))
```yaml
title: Run Once Task Execution as Configured in Registry
id: 198effb6-6c98-4d0c-9ea3-451fa143c45c
status: test
description: This rule detects the execution of Run Once task as configured in the registry
author: 'Avneet Singh @v3t0_, oscd.community'
references:
  - https://twitter.com/pabraeken/status/990717080805789697
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Runonce.yml
date: 2020/10/18
modified: 2021/11/27
logsource:
  product: windows
  category: process_creation
detection:
  process_name:
    Image|endswith:
      - '\runonce.exe'
  process_description:
    Description:
      - 'Run Once Wrapper'
  command_line:
    CommandLine|contains:
      - ' /AlternateShellStartup'
  condition: (process_name or process_description) and command_line
falsepositives:
  - Unknown
level: low
tags:
  - attack.defense_evasion
  - attack.t1112

```
