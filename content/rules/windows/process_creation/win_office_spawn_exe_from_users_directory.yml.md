---
title: "MS Office Product Spawning Exe in User Dir"
aliases:
  - "/rule/aa3a6f94-890e-4e22-b634-ffdfd54792cc"

tags:
  - attack.execution
  - attack.t1204
  - attack.t1204.002
  - FIN7
  - car.2013-05-002



status: experimental



level: high



date: Tue, 9 Apr 2019 09:45:07 -0400


---

Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio

<!--more-->


## Known false-positives

* unknown



## References

* sha256=23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c
* https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign


## Raw rule
```yaml
title: MS Office Product Spawning Exe in User Dir
id: aa3a6f94-890e-4e22-b634-ffdfd54792cc
status: experimental
description: Detects an executable in the users directory started from Microsoft Word, Excel, Powerpoint, Publisher or Visio
references:
    - sha256=23160972c6ae07f740800fa28e421a81d7c0ca5d5cab95bc082b4a986fbac57c
    - https://blog.morphisec.com/fin7-not-finished-morphisec-spots-new-campaign
tags:
    - attack.execution
    - attack.t1204          # an old one
    - attack.t1204.002
    - FIN7
    - car.2013-05-002
author: Jason Lynch 
date: 2019/04/02
modified: 2020/09/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\WINWORD.EXE'
            - '*\EXCEL.EXE'
            - '*\POWERPNT.exe'
            - '*\MSPUB.exe'
            - '*\VISIO.exe'
            - '*\OUTLOOK.EXE'
        Image:
            - 'C:\users\\*.exe'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```
