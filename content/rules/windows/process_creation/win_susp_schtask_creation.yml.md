---
title: "Scheduled Task Creation"
aliases:
  - "/rule/92626ddd-662c-49e3-ac59-f6535f12d189"

tags:
  - attack.execution
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053.005
  - attack.t1053
  - attack.s0111
  - car.2013-08-001



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects the creation of scheduled tasks in user session

<!--more-->


## Known false-positives

* Administrative activity
* Software installation




## Raw rule
```yaml
title: Scheduled Task Creation
id: 92626ddd-662c-49e3-ac59-f6535f12d189
status: experimental
description: Detects the creation of scheduled tasks in user session
author: Florian Roth
date: 2019/01/16
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\schtasks.exe'
        CommandLine: '* /create *'
    filter:
        User: NT AUTHORITY\SYSTEM
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053.005
    - attack.t1053     # an old one 
    - attack.s0111
    - car.2013-08-001
falsepositives:
    - Administrative activity
    - Software installation
level: low

```