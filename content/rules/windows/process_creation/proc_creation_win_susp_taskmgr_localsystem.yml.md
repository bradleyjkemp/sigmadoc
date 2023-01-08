---
title: "Taskmgr as LOCAL_SYSTEM"
aliases:
  - "/rule/9fff585c-c33e-4a86-b3cd-39312079a65f"
ruleid: 9fff585c-c33e-4a86-b3cd-39312079a65f

tags:
  - attack.defense_evasion
  - attack.t1036



status: experimental





date: Mon, 19 Mar 2018 16:36:39 +0100


---

Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM

<!--more-->


## Known false-positives

* Unknown




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_taskmgr_localsystem.yml))
```yaml
title: Taskmgr as LOCAL_SYSTEM
id: 9fff585c-c33e-4a86-b3cd-39312079a65f
status: experimental
description: Detects the creation of taskmgr.exe process in context of LOCAL_SYSTEM
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/18
modified: 2021/08/26
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User|startswith: 
            - 'NT AUTHORITY\SYSTEM'
            - 'AUTORITE NT\Sys' # French language settings
        Image|endswith: '\taskmgr.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
