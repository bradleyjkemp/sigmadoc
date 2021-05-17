---
title: "Suspicious desktop.ini Action"
aliases:
  - "/rule/81315b50-6b60-4d8f-9928-3466e1022515"

tags:
  - attack.persistence
  - attack.t1023
  - attack.t1547.009



status: experimental



level: medium



date: Thu, 19 Mar 2020 21:36:14 +0100


---

Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.

<!--more-->


## Known false-positives

* Operations performed through Windows SCCM or equivalent



## References

* https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/


## Raw rule
```yaml
title: Suspicious desktop.ini Action
id: 81315b50-6b60-4d8f-9928-3466e1022515
status: experimental
description: Detects unusual processes accessing desktop.ini, which can be leveraged to alter how Explorer displays a folder's content (i.e. renaming files) without changing them on disk.
references:
    - https://isc.sans.edu/forums/diary/Desktopini+as+a+postexploitation+tool/25912/
author: Maxime Thiebaut (@0xThiebaut)
date: 2020/03/19
modified: 2020/08/23
tags:
    - attack.persistence
    - attack.t1023          # an old one
    - attack.t1547.009
logsource:
    product: windows
    category: file_event
detection:
    filter:
        Image:
            - 'C:\Windows\explorer.exe'
            - 'C:\Windows\System32\msiexec.exe'
            - 'C:\Windows\System32\mmc.exe'
    selection:
        TargetFilename|endswith: '\desktop.ini'
    condition: selection and not filter
falsepositives:
    - Operations performed through Windows SCCM or equivalent
level: medium

```
