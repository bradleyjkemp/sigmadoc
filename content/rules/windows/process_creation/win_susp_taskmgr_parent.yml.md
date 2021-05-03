---
title: "Taskmgr as Parent"
aliases:
  - "/rule/3d7679bd-0c00-440c-97b0-3f204273e6c7"

tags:
  - attack.defense_evasion
  - attack.t1036



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects the creation of a process from Windows task manager

<!--more-->


## Known false-positives

* Administrative activity




## Raw rule
```yaml
title: Taskmgr as Parent
id: 3d7679bd-0c00-440c-97b0-3f204273e6c7
status: experimental
description: Detects the creation of a process from Windows task manager
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/13
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\taskmgr.exe'
    filter:
        Image:
            - '*\resmon.exe'
            - '*\mmc.exe'
            - '*\taskmgr.exe'
    condition: selection and not filter
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: low

```
