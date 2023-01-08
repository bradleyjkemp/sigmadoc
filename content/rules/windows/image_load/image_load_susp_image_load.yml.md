---
title: "Possible Process Hollowing Image Loading"
aliases:
  - "/rule/e32ce4f5-46c6-4c47-ba69-5de3c9193cd7"
ruleid: e32ce4f5-46c6-4c47-ba69-5de3c9193cd7

tags:
  - attack.defense_evasion
  - attack.t1574.002



status: test





date: Sun, 1 Jul 2018 15:47:17 +0200


---

Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz

<!--more-->


## Known false-positives

* Very likely, needs more tuning



## References

* https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_susp_image_load.yml))
```yaml
title: Possible Process Hollowing Image Loading
id: e32ce4f5-46c6-4c47-ba69-5de3c9193cd7
status: test
description: Detects Loading of samlib.dll, WinSCard.dll from untypical process e.g. through process hollowing by Mimikatz
author: Markus Neis
references:
  - https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for.html
date: 2018/01/07
modified: 2021/11/27
logsource:
  category: image_load
  product: windows
detection:
  selection:
    Image|endswith:
      - '\notepad.exe'
    ImageLoaded|endswith:
      - '\samlib.dll'
      - '\WinSCard.dll'
  condition: selection
falsepositives:
  - Very likely, needs more tuning
level: high
tags:
  - attack.defense_evasion
  - attack.t1574.002

```
