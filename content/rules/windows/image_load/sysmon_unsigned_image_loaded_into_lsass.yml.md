---
title: "Unsigned Image Loaded Into LSASS Process"
aliases:
  - "/rule/857c8db3-c89b-42fb-882b-f681c7cf4da2"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001



status: experimental



level: medium



date: Mon, 4 Nov 2019 04:26:34 +0300


---

Loading unsigned image (DLL, EXE) into LSASS process

<!--more-->


## Known false-positives

* Valid user connecting using RDP



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule
```yaml
title: Unsigned Image Loaded Into LSASS Process
id: 857c8db3-c89b-42fb-882b-f681c7cf4da2
description: Loading unsigned image (DLL, EXE) into LSASS process
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
modified: 2020/08/23
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.001
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\lsass.exe'
        Signed: 'false'
    condition: selection
falsepositives:
    - Valid user connecting using RDP
status: experimental
level: medium

```
