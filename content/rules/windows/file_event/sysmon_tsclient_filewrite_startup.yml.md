---
title: "Hijack Legit RDP Session to Move Laterally"
aliases:
  - "/rule/52753ea4-b3a0-4365-910d-36cff487b789"



status: experimental



level: high



date: Wed, 3 Apr 2019 13:19:59 +0200


---

Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder

<!--more-->


## Known false-positives

* unknown




## Raw rule
```yaml
title: Hijack Legit RDP Session to Move Laterally
id: 52753ea4-b3a0-4365-910d-36cff487b789
status: experimental
description: Detects the usage of tsclient share to place a backdoor on the RDP source machine's startup folder
date: 2019/02/21
author: Samir Bousseaden
logsource:
    product: windows
    category: file_event
detection:
    selection:
        Image: '*\mstsc.exe'
        TargetFilename: '*\Microsoft\Windows\Start Menu\Programs\Startup\\*'
    condition: selection
falsepositives:
    - unknown
level: high

```
