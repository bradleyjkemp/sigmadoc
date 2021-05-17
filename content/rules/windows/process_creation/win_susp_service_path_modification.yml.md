---
title: "Suspicious Service Path Modification"
aliases:
  - "/rule/138d3531-8793-4f50-a2cd-f291b2863d78"

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003
  - attack.t1031



status: experimental



level: high



date: Fri, 25 Oct 2019 15:38:47 +0400


---

Detects service path modification to powershell/cmd

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1031/T1031.yaml


## Raw rule
```yaml
title: Suspicious Service Path Modification
id: 138d3531-8793-4f50-a2cd-f291b2863d78
description: Detects service path modification to powershell/cmd
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1031/T1031.yaml
tags:
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1543.003
    - attack.t1031      # an old one     
date: 2019/10/21
modified: 2020/08/28
author: Victor Sergeev, oscd.community
logsource:
    category: process_creation
    product: windows
detection:
    selection_1:
        Image|endswith: '\sc.exe'
        CommandLine|contains|all:
            - 'config'
            - 'binpath'
    selection_2:
        CommandLine|contains:
            - 'powershell'
            - 'cmd'
    condition: selection_1 and selection_2
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```
