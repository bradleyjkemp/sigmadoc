---
title: "Possible Process Hollowing Image Loading"
aliases:
  - "/rule/e32ce4f5-46c6-4c47-ba69-5de3c9193cd7"

tags:
  - attack.defense_evasion
  - attack.t1073
  - attack.t1574.002



status: experimental



level: high



date: Sun, 1 Jul 2018 15:47:17 +0200


---

Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz

<!--more-->


## Known false-positives

* Very likely, needs more tuning



## References

* https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html


## Raw rule
```yaml
title: Possible Process Hollowing Image Loading
id: e32ce4f5-46c6-4c47-ba69-5de3c9193cd7
status: experimental
description: Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz
references:
    - https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html
author: Markus Neis
date: 2018/01/07
modified: 2020/08/23
tags:
    - attack.defense_evasion
    - attack.t1073          # an old one
    - attack.t1574.002
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image:
            - '*\notepad.exe'
        ImageLoaded:
            - '*\samlib.dll'
            - '*\WinSCard.dll'
    condition: selection
falsepositives:
    - Very likely, needs more tuning
level: high

```
