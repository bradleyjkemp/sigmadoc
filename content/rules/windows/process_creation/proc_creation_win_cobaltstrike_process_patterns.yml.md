---
title: "CobaltStrike Process Patterns"
aliases:
  - "/rule/f35c5d71-b489-4e22-a115-f003df287317"
ruleid: f35c5d71-b489-4e22-a115-f003df287317

tags:
  - attack.execution
  - attack.t1059



status: experimental





date: Tue, 27 Jul 2021 11:24:40 +0200


---

Detects process patterns found in Cobalt Strike beacon activity (see reference for more details)

<!--more-->


## Known false-positives

* Other programs that cause these patterns (please report)



## References

* https://hausec.com/2021/07/26/cobalt-strike-and-tradecraft/
* https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_cobaltstrike_process_patterns.yml))
```yaml
title: CobaltStrike Process Patterns
id: f35c5d71-b489-4e22-a115-f003df287317
status: experimental
description: Detects process patterns found in Cobalt Strike beacon activity (see reference for more details)
author: Florian Roth
references:
    - https://hausec.com/2021/07/26/cobalt-strike-and-tradecraft/
    - https://thedfirreport.com/2021/08/29/cobalt-strike-a-defenders-guide/
date: 2021/07/27
modified: 2022/03/05
tags:
    - attack.execution
    - attack.t1059 
logsource:
    category: process_creation
    product: windows
detection:
    selection1: 
        CommandLine|contains: '\cmd.exe /C whoami'
        ParentImage|startswith: 'C:\Temp'
    selection2:
        CommandLine|contains: 'conhost.exe 0xffffffff -ForceV1'
        ParentCommandLine|contains: 
            - '/C whoami'
            - 'cmd.exe /C echo'
            - ' > \\\\.\\pipe'
    selection3:
        CommandLine|contains: 
            - 'cmd.exe /c echo'
            - '> \\\\.\\pipe'
            - '\whoami.exe'
        ParentImage|endswith: '\dllhost.exe'
    selection4:
        Image|endswith: '\cmd.exe'
        ParentImage|endswith: '\runonce.exe'
        ParentCommandLine|endswith: '\runonce.exe'
    condition: 1 of selection*
falsepositives:
    - Other programs that cause these patterns (please report)
level: high


```
