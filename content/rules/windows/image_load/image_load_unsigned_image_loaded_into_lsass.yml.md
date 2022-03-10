---
title: "Unsigned Image Loaded Into LSASS Process"
aliases:
  - "/rule/857c8db3-c89b-42fb-882b-f681c7cf4da2"


tags:
  - attack.credential_access
  - attack.t1003.001



status: test





date: Mon, 4 Nov 2019 04:26:34 +0300


---

Loading unsigned image (DLL, EXE) into LSASS process

<!--more-->


## Known false-positives

* Valid user connecting using RDP



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/image_load/image_load_unsigned_image_loaded_into_lsass.yml))
```yaml
title: Unsigned Image Loaded Into LSASS Process
id: 857c8db3-c89b-42fb-882b-f681c7cf4da2
status: test
description: Loading unsigned image (DLL, EXE) into LSASS process
author: Teymur Kheirkhabarov, oscd.community
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
date: 2019/10/22
modified: 2021/11/27
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
level: medium
tags:
  - attack.credential_access
  - attack.t1003.001

```
