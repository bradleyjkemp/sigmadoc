---
title: "MMC Spawning Windows Shell"
aliases:
  - "/rule/05a2ab7e-ce11-4b63-86db-ab32e763e11d"

tags:
  - attack.lateral_movement
  - attack.t1175
  - attack.t1021.003



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a Windows command line executable started from MMC

<!--more-->




## References

* https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/


## Raw rule
```yaml
title: MMC Spawning Windows Shell
id: 05a2ab7e-ce11-4b63-86db-ab32e763e11d
status: experimental
description: Detects a Windows command line executable started from MMC
author: Karneades, Swisscom CSIRT
date: 2019/08/05
modified: 2020/09/01
references:
    - https://enigma0x3.net/2017/01/05/lateral-movement-using-the-mmc20-application-com-object/
tags:
    - attack.lateral_movement
    - attack.t1175          # an old one
    - attack.t1021.003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mmc.exe'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\reg.exe'
            - '*\regsvr32.exe'
            - '*\BITSADMIN*'
    condition: selection
fields:
    - CommandLine
    - Image
    - ParentCommandLine
level: high

```
