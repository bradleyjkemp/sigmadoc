---
title: "Execution in Non-Executable Folder"
aliases:
  - "/rule/3dfd06d2-eaf4-4532-9555-68aca59f57c4"

tags:
  - attack.defense_evasion
  - attack.t1036



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious exection from an uncommon folder

<!--more-->


## Known false-positives

* Unknown




## Raw rule
```yaml
title: Execution in Non-Executable Folder
id: 3dfd06d2-eaf4-4532-9555-68aca59f57c4
status: experimental
description: Detects a suspicious exection from an uncommon folder
author: Florian Roth
date: 2019/01/16
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*\$Recycle.bin'
            - '*\Users\All Users\\*'
            - '*\Users\Default\\*'
            - '*\Users\Public\\*'
            - 'C:\Perflogs\\*'
            - '*\config\systemprofile\\*'
            - '*\Windows\Fonts\\*'
            - '*\Windows\IME\\*'
            - '*\Windows\addins\\*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
