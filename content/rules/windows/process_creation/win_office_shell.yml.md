---
title: "Microsoft Office Product Spawning Windows Shell"
aliases:
  - "/rule/438025f9-5856-4663-83f7-52f878a70a50"

tags:
  - attack.execution
  - attack.t1204
  - attack.t1204.002



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a Windows command and scripting interpreter executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio

<!--more-->


## Known false-positives

* unknown



## References

* https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100
* https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html


## Raw rule
```yaml
title: Microsoft Office Product Spawning Windows Shell
id: 438025f9-5856-4663-83f7-52f878a70a50
status: experimental
description: Detects a Windows command and scripting interpreter executable started from Microsoft Word, Excel, Powerpoint, Publisher and Visio
references:
    - https://www.hybrid-analysis.com/sample/465aabe132ccb949e75b8ab9c5bda36d80cf2fd503d52b8bad54e295f28bbc21?environmentId=100
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
tags:
    - attack.execution
    - attack.t1204          # an old one
    - attack.t1204.002
author: Michael Haag, Florian Roth, Markus Neis
date: 2018/04/06
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
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\scrcons.exe'
            - '*\schtasks.exe'
            - '*\regsvr32.exe'
            - '*\hh.exe'
            - '*\wmic.exe'  # https://app.any.run/tasks/c903e9c8-0350-440c-8688-3881b556b8e0/
            - '*\mshta.exe'
            - '*\rundll32.exe'
            - '*\msiexec.exe'
            - '*\forfiles.exe'
            - '*\scriptrunner.exe'
            - '*\mftrace.exe'
            - '*\AppVLP.exe'
            - '*\svchost.exe'  # https://www.vmray.com/analyses/2d2fa29185ad/report/overview.html
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: high

```