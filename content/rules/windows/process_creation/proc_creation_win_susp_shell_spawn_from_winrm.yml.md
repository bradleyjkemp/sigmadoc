---
title: "Suspicious Shells Spawn by WinRM"
aliases:
  - "/rule/5cc2cda8-f261-4d88-a2de-e9e193c86716"
ruleid: 5cc2cda8-f261-4d88-a2de-e9e193c86716

tags:
  - attack.t1190
  - attack.initial_access
  - attack.persistence
  - attack.privilege_escalation



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious shell spawn from WinRM host process

<!--more-->


## Known false-positives

* Legitimate WinRM usage




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_shell_spawn_from_winrm.yml))
```yaml
title: Suspicious Shells Spawn by WinRM
id: 5cc2cda8-f261-4d88-a2de-e9e193c86716
description: Detects suspicious shell spawn from WinRM host process
status: experimental
author: Andreas Hunkeler (@Karneades), Markus Neis
date: 2021/05/20
modified: 2021/05/22
tags:
    - attack.t1190
    - attack.initial_access
    - attack.persistence
    - attack.privilege_escalation
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\wsmprovhost.exe'
        Image:
            - '*\cmd.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\powershell.exe'
            - '*\schtasks.exe'
            - '*\certutil.exe'
            - '*\whoami.exe'
            - '*\bitsadmin.exe'
    condition: selection
falsepositives:
    - Legitimate WinRM usage
level: high

```
