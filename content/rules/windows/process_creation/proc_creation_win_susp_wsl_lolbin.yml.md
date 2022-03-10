---
title: "WSL Execution"
aliases:
  - "/rule/dec44ca7-61ad-493c-bfd7-8819c5faa09b"


tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218
  - attack.t1202



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Possible usage of Windows Subsystem for Linux (WSL) binary as a LOLBIN

<!--more-->


## Known false-positives

* Automation and orchestration scripts may use this method execute scripts etc



## References

* https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_wsl_lolbin.yml))
```yaml
title: WSL Execution
id: dec44ca7-61ad-493c-bfd7-8819c5faa09b
status: test
description: Detects Possible usage of Windows Subsystem for Linux (WSL) binary as a LOLBIN
author: 'oscd.community, Zach Stanford @svch0st'
references:
  - https://lolbas-project.github.io/lolbas/OtherMSBinaries/Wsl/
date: 2020/10/05
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\wsl.exe'
    CommandLine|contains:
      - ' -e '
      - ' --exec '
  condition: selection
falsepositives:
  - Automation and orchestration scripts may use this method execute scripts etc
level: medium
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218
  - attack.t1202

```
