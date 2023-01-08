---
title: "Indirect Command Execution By Program Compatibility Wizard"
aliases:
  - "/rule/b97cd4b1-30b8-4a9d-bd72-6293928d52bc"
ruleid: b97cd4b1-30b8-4a9d-bd72-6293928d52bc

tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.execution



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detect indirect command execution via Program Compatibility Assistant pcwrun.exe

<!--more-->


## Known false-positives

* Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts
* Legit usage of scripts



## References

* https://twitter.com/pabraeken/status/991335019833708544
* https://lolbas-project.github.io/lolbas/Binaries/Pcwrun/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_indirect_cmd_compatibility_assistant.yml))
```yaml
title: Indirect Command Execution By Program Compatibility Wizard
id: b97cd4b1-30b8-4a9d-bd72-6293928d52bc
status: test
description: Detect indirect command execution via Program Compatibility Assistant pcwrun.exe
author: A. Sungurov , oscd.community
references:
  - https://twitter.com/pabraeken/status/991335019833708544
  - https://lolbas-project.github.io/lolbas/Binaries/Pcwrun/
date: 2020/10/12
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\pcwrun.exe'
  condition: selection
fields:
  - ComputerName
  - User
  - ParentCommandLine
  - CommandLine
falsepositives:
  - Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts
  - Legit usage of scripts
level: low
tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.execution

```
