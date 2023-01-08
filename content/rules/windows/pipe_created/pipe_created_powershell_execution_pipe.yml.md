---
title: "T1086 PowerShell Execution"
aliases:
  - "/rule/ac7102b4-9e1e-4802-9b4f-17c5524c015c"
ruleid: ac7102b4-9e1e-4802-9b4f-17c5524c015c

tags:
  - attack.execution
  - attack.t1059.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects execution of PowerShell

<!--more-->


## Known false-positives

* Unknown



## References

* https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190410151110.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/pipe_created/pipe_created_powershell_execution_pipe.yml))
```yaml
title: T1086 PowerShell Execution
id: ac7102b4-9e1e-4802-9b4f-17c5524c015c
status: test
description: Detects execution of PowerShell
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190410151110.html
date: 2019/09/12
modified: 2021/11/27
logsource:
  product: windows
  category: pipe_created
detection:
  selection:
    PipeName|startswith: '\PSHost'
  condition: selection
falsepositives:
  - Unknown
level: informational
tags:
  - attack.execution
  - attack.t1059.001

```
