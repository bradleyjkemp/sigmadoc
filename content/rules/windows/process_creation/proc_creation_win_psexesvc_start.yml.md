---
title: "PsExec Service Start"
aliases:
  - "/rule/3ede524d-21cc-472d-a3ce-d21b568d8db7"


tags:
  - attack.execution
  - attack.s0029
  - attack.t1569.002



status: test





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a PsExec service start

<!--more-->


## Known false-positives

* Administrative activity




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_psexesvc_start.yml))
```yaml
title: PsExec Service Start
id: 3ede524d-21cc-472d-a3ce-d21b568d8db7
status: test
description: Detects a PsExec service start
author: Florian Roth
date: 2018/03/13
modified: 2021/11/27
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
tags:
  - attack.execution
  - attack.s0029
  - attack.t1569.002

```
