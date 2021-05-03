---
title: "PsExec Service Start"
aliases:
  - "/rule/3ede524d-21cc-472d-a3ce-d21b568d8db7"

tags:
  - attack.execution
  - attack.t1035
  - attack.s0029
  - attack.t1569.002



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a PsExec service start

<!--more-->


## Known false-positives

* Administrative activity




## Raw rule
```yaml
title: PsExec Service Start
id: 3ede524d-21cc-472d-a3ce-d21b568d8db7
description: Detects a PsExec service start
author: Florian Roth
date: 2018/03/13
modified: 2012/12/11
tags:
    - attack.execution
    - attack.t1035 # an old one
    - attack.s0029
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: C:\Windows\PSEXESVC.exe
    condition: selection
falsepositives:
    - Administrative activity
level: low

```
