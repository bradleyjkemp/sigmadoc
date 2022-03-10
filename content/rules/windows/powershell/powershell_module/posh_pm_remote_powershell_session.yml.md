---
title: "Remote PowerShell Session"
aliases:
  - "/rule/96b9f619-aa91-478f-bacb-c3e50f8df575"


tags:
  - attack.execution
  - attack.t1059.001
  - attack.lateral_movement
  - attack.t1021.006



status: test





date: Thu, 24 Oct 2019 15:48:38 +0200


---

Detects remote PowerShell sessions

<!--more-->


## Known false-positives

* Legitimate use remote PowerShell sessions



## References

* https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190511223310.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_module/posh_pm_remote_powershell_session.yml))
```yaml
title: Remote PowerShell Session
id: 96b9f619-aa91-478f-bacb-c3e50f8df575
description: Detects remote PowerShell sessions
status: test
date: 2019/08/10
modified: 2021/10/16
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190511223310.html
tags:
    - attack.execution
    - attack.t1059.001
    - attack.lateral_movement
    - attack.t1021.006
logsource:
    product: windows
    category: ps_module
    definition: PowerShell Module Logging must be enabled
detection:
    selection:
        ContextInfo|contains|all:
            - ' = ServerRemoteHost ' #  HostName: 'ServerRemoteHost'  french : Nom d’hôte = 
            - 'wsmprovhost.exe'      #  HostApplication|contains: 'wsmprovhost.exe' french  Application hôte = 
    condition: selection
falsepositives:
    - Legitimate use remote PowerShell sessions
level: high
```
