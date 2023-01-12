---
title: "Suspicious Service Path Modification"
aliases:
  - "/rule/138d3531-8793-4f50-a2cd-f291b2863d78"
ruleid: 138d3531-8793-4f50-a2cd-f291b2863d78

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003



status: test





date: Fri, 25 Oct 2019 15:38:47 +0400


---

Detects service path modification to PowerShell or cmd.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_service_path_modification.yml))
```yaml
title: Suspicious Service Path Modification
id: 138d3531-8793-4f50-a2cd-f291b2863d78
status: test
description: Detects service path modification to PowerShell or cmd.
author: Victor Sergeev, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md
date: 2019/10/21
modified: 2021/11/27
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
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003

```