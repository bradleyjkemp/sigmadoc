---
title: "Suspicious Execution of InstallUtil Without Log"
aliases:
  - "/rule/d042284c-a296-4988-9be5-f424fadcc28c"


tags:
  - attack.defense_evasion



status: experimental





date: Sun, 23 Jan 2022 14:47:25 +0100


---

Uses the .NET InstallUtil.exe application in order to execute image without log

<!--more-->


## Known false-positives

* Unknown



## References

* https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/
* https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_instalutil.yml))
```yaml
title: Suspicious Execution of InstallUtil Without Log 
id: d042284c-a296-4988-9be5-f424fadcc28c
status: experimental
description: Uses the .NET InstallUtil.exe application in order to execute image without log
author: frack113
references:
    - https://securelist.com/moonbounce-the-dark-side-of-uefi-firmware/105468/
    - https://docs.microsoft.com/en-us/dotnet/framework/tools/installutil-exe-installer-tool
date: 2022/01/23
modified: 2022/02/04
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \InstallUtil.exe
        Image|contains: Microsoft.NET\Framework
        CommandLine|contains|all:
            - '/logfile= '
            - '/LogToConsole=false'
    condition: selection
falsepositives:
    - Unknown
level: medium
tags:
    - attack.defense_evasion

```
