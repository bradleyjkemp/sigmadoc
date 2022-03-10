---
title: "Sysinternals SDelete Delete File"
aliases:
  - "/rule/a4824fca-976f-4964-b334-0621379e84c4"


tags:
  - attack.impact
  - attack.t1485



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Use of SDelete to erase a file not the free space

<!--more-->


## Known false-positives

* System administrator Usage



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_sdelete.yml))
```yaml
title: Sysinternals SDelete Delete File
id: a4824fca-976f-4964-b334-0621379e84c4
status: experimental
author: frack113
date: 2021/06/03
description: Use of SDelete to erase a file not the free space
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1485/T1485.md
tags:
    - attack.impact
    - attack.t1485
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: sdelete.exe
    filter:
        CommandLine|contains:
            - ' -h'
            - ' -c'
            - ' -z'
            - ' /?'
    condition: selection and not filter
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - System administrator Usage
level: medium

```
