---
title: "MMC20 Lateral Movement"
aliases:
  - "/rule/f1f3bf22-deb2-418d-8cce-e1a45e46a5bd"
ruleid: f1f3bf22-deb2-418d-8cce-e1a45e46a5bd

tags:
  - attack.execution
  - attack.t1021.003



status: test





date: Wed, 4 Mar 2020 14:57:41 -0500


---

Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe

<!--more-->


## Known false-positives

* Unlikely



## References

* https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
* https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_mmc20_lateral_movement.yml))
```yaml
title: MMC20 Lateral Movement
id: f1f3bf22-deb2-418d-8cce-e1a45e46a5bd
status: test
description: Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe
author: '@2xxeformyshirt (Security Risk Advisors) - rule; Teymur Kheirkhabarov (idea)'
references:
  - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
  - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing
date: 2020/03/04
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\svchost.exe'
    Image|endswith: '\mmc.exe'
    CommandLine|contains: '-Embedding'
  condition: selection
falsepositives:
  - Unlikely
level: high
tags:
  - attack.execution
  - attack.t1021.003

```
