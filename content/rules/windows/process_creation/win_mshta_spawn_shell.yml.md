---
title: "MSHTA Spawning Windows Shell"
aliases:
  - "/rule/03cc0c25-389f-4bf8-b48d-11878079f1ca"

tags:
  - attack.defense_evasion
  - attack.t1170
  - attack.t1218.005
  - car.2013-02-003
  - car.2013-03-001
  - car.2014-04-003



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a Windows command line executable started from MSHTA

<!--more-->


## Known false-positives

* Printer software / driver installations
* HP software



## References

* https://www.trustedsec.com/july-2015/malicious-htas/


## Raw rule
```yaml
title: MSHTA Spawning Windows Shell
id: 03cc0c25-389f-4bf8-b48d-11878079f1ca
status: experimental
description: Detects a Windows command line executable started from MSHTA
references:
    - https://www.trustedsec.com/july-2015/malicious-htas/
author: Michael Haag
date: 2019/01/16
modified: 2020/09/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\mshta.exe'
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
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.t1170          # an old one
    - attack.t1218.005
    - car.2013-02-003
    - car.2013-03-001
    - car.2014-04-003
falsepositives:
    - Printer software / driver installations
    - HP software
level: high

```
