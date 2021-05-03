---
title: "MMC20 Lateral Movement"
aliases:
  - "/rule/f1f3bf22-deb2-418d-8cce-e1a45e46a5bd"

tags:
  - attack.execution
  - attack.t1175
  - attack.t1021.003



date: Wed, 4 Mar 2020 14:57:41 -0500


---

Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe

<!--more-->


## Known false-positives

* Unlikely



## References

* https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
* https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing


## Raw rule
```yaml
title: MMC20 Lateral Movement
id: f1f3bf22-deb2-418d-8cce-e1a45e46a5bd
description: Detects MMC20.Application Lateral Movement; specifically looks for the spawning of the parent MMC.exe with a command line of "-Embedding" as a child of svchost.exe
author: '@2xxeformyshirt (Security Risk Advisors) - rule; Teymur Kheirkhabarov (idea)'
date: 2020/03/04
modified: 2020/08/23
references:
    - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
    - https://drive.google.com/file/d/1lKya3_mLnR3UQuCoiYruO3qgu052_iS_/view?usp=sharing
tags:
    - attack.execution
    - attack.t1175          # an old one
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\svchost.exe'
        Image: '*\mmc.exe'
        CommandLine: '*-Embedding*'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
