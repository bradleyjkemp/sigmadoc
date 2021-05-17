---
title: "Windows Shell Spawning Suspicious Program"
aliases:
  - "/rule/3a6586ad-127a-4d3b-a677-1e6eacdf8fde"

tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1064
  - attack.t1059.005
  - attack.t1059.001
  - attack.t1218



status: experimental



level: high



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious child process of a Windows shell

<!--more-->


## Known false-positives

* Administrative scripts
* Microsoft SCCM



## References

* https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html


## Raw rule
```yaml
title: Windows Shell Spawning Suspicious Program
id: 3a6586ad-127a-4d3b-a677-1e6eacdf8fde
status: experimental
description: Detects a suspicious child process of a Windows shell
references:
    - https://mgreen27.github.io/posts/2018/04/02/DownloadCradle.html
author: Florian Roth
date: 2018/04/06
modified: 2020/09/06
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1064 # an old one
    - attack.t1059.005
    - attack.t1059.001
    - attack.t1218    
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\mshta.exe'
            - '*\powershell.exe'
            # - '*\cmd.exe'  # too many false positives
            - '*\rundll32.exe'
            - '*\cscript.exe'
            - '*\wscript.exe'
            - '*\wmiprvse.exe'
        Image:
            - '*\schtasks.exe'
            - '*\nslookup.exe'
            - '*\certutil.exe'
            - '*\bitsadmin.exe'
            - '*\mshta.exe'
    falsepositives:
        CurrentDirectory: '*\ccmcache\\*'
    condition: selection and not falsepositives
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
    - Microsoft SCCM
level: high

```
