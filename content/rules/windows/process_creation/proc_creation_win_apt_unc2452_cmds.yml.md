---
title: "UNC2452 Process Creation Patterns"
aliases:
  - "/rule/9be34ad0-b6a7-4fbd-91cf-fc7ec1047f5f"
ruleid: 9be34ad0-b6a7-4fbd-91cf-fc7ec1047f5f

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a specific process creation patterns as seen used by UNC2452 and provided by Microsoft as Microsoft Defender ATP queries

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_unc2452_cmds.yml))
```yaml
title: UNC2452 Process Creation Patterns
id: 9be34ad0-b6a7-4fbd-91cf-fc7ec1047f5f
description: Detects a specific process creation patterns as seen used by UNC2452 and provided by Microsoft as Microsoft Defender ATP queries
status: experimental
references:
    - https://www.microsoft.com/security/blog/2021/01/20/deep-dive-into-the-solorigate-second-stage-activation-from-sunburst-to-teardrop-and-raindrop/
tags:
    - attack.execution
    - attack.t1059.001
    # - sunburst
    # - unc2452
author: Florian Roth
date: 2021/01/22
modified: 2021/06/27
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains: 
            - '7z.exe a -v500m -mx9 -r0 -p'
    selection2:
        ParentCommandLine|contains|all:
            - 'wscript.exe'
            - '.vbs'
        CommandLine|contains|all:
            - 'rundll32.exe'
            - 'C:\Windows'
            - '.dll,Tk_'
    selection3:
        ParentImage|endswith: '\rundll32.exe'
        ParentCommandLine|contains: 'C:\Windows'
        CommandLine|contains: 'cmd.exe /C '
    selection4:
        CommandLine|contains|all: 
            - 'rundll32 c:\windows\'
            - '.dll '
    specific1:
        ParentImage|endswith: '\rundll32.exe'
        Image|endswith: '\dllhost.exe'
    filter1:
        CommandLine: 
            - ' '
            - ''
    condition: selection1 or selection2 or selection3 or selection4 or ( specific1 and not filter1 )
falsepositives:
    - Unknown
level: critical
```
