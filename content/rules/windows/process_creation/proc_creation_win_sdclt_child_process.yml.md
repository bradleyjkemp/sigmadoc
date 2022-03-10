---
title: "Sdclt Child Processes"
aliases:
  - "/rule/da2738f2-fadb-4394-afa7-0a0674885afa"


tags:
  - attack.privilege_escalation
  - attack.t1548.002



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

A General detection for sdclt spawning new processes. This could be an indicator of sdclt being used for bypass UAC techniques.

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/OTRF/detection-hackathon-apt29/issues/6
* https://threathunterplaybook.com/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_sdclt_child_process.yml))
```yaml
title: Sdclt Child Processes
id: da2738f2-fadb-4394-afa7-0a0674885afa
status: test
description: A General detection for sdclt spawning new processes. This could be an indicator of sdclt being used for bypass UAC techniques.
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
references:
  - https://github.com/OTRF/detection-hackathon-apt29/issues/6
  - https://threathunterplaybook.com/evals/apt29/detections/3.B.2_C36B49B5-DF58-4A34-9FE9-56189B9DEFEA.html
date: 2020/05/02
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\sdclt.exe'
  condition: selection
falsepositives:
  - unknown
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1548.002

```
