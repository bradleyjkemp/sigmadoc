---
title: "VMToolsd Suspicious Child Process"
aliases:
  - "/rule/5687f942-867b-4578-ade7-1e341c46e99a"


tags:
  - attack.execution
  - attack.persistence
  - attack.t1059



status: experimental





date: Fri, 8 Oct 2021 13:28:35 +0545


---

Detects suspicious child process creations of VMware Tools process which may indicate persistence setup

<!--more-->


## Known false-positives

* Legitimate use by adminstrator



## References

* https://bohops.com/2021/10/08/analyzing-and-detecting-a-vmtools-persistence-technique/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_vmtoolsd_susp_child_process.yml))
```yaml
title: VMToolsd Suspicious Child Process
id: 5687f942-867b-4578-ade7-1e341c46e99a
status: experimental
description: Detects suspicious child process creations of VMware Tools process which may indicate persistence setup
tags:
    - attack.execution
    - attack.persistence
    - attack.t1059
author: behops, Bhabesh Raj
date: 2021/10/08
modified: 2021/10/10
references:
    - https://bohops.com/2021/10/08/analyzing-and-detecting-a-vmtools-persistence-technique/
fields:
    - CommandLine
    - ParentCommandLine
    - Details
falsepositives:
    - Legitimate use by adminstrator
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\vmtoolsd.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\rundll32.exe'
            - '\regsvr32.exe'
            - '\wscript.exe'
            - '\cscript.exe'
    filter:
        CommandLine|contains:
            - '\VMware\VMware Tools\poweron-vm-default.bat'
            - '\VMware\VMware Tools\poweroff-vm-default.bat'
            - '\VMware\VMware Tools\resume-vm-default.bat'
            - '\VMware\VMware Tools\suspend-vm-default.bat'
    condition: selection and not filter

```
