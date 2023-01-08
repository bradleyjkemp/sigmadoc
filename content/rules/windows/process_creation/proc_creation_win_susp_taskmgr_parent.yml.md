---
title: "Taskmgr as Parent"
aliases:
  - "/rule/3d7679bd-0c00-440c-97b0-3f204273e6c7"
ruleid: 3d7679bd-0c00-440c-97b0-3f204273e6c7

tags:
  - attack.defense_evasion
  - attack.t1036



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects the creation of a process from Windows task manager

<!--more-->


## Known false-positives

* Administrative activity




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_taskmgr_parent.yml))
```yaml
title: Taskmgr as Parent
id: 3d7679bd-0c00-440c-97b0-3f204273e6c7
status: test
description: Detects the creation of a process from Windows task manager
author: Florian Roth
date: 2018/03/13
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\taskmgr.exe'
  filter:
    Image|endswith:
      - '\resmon.exe'
      - '\mmc.exe'
      - '\taskmgr.exe'
  condition: selection and not filter
fields:
  - Image
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Administrative activity
level: low
tags:
  - attack.defense_evasion
  - attack.t1036

```
