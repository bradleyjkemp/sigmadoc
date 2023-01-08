---
title: "Suspicious DIR Execution"
aliases:
  - "/rule/7c9340a9-e2ee-4e43-94c5-c54ebbea1006"
ruleid: 7c9340a9-e2ee-4e43-94c5-c54ebbea1006

tags:
  - attack.discovery
  - attack.t1217



status: experimental





date: Mon, 13 Dec 2021 11:02:33 +0100


---

Use dir to collect information

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_dir.yml))
```yaml
title: Suspicious DIR Execution
id: 7c9340a9-e2ee-4e43-94c5-c54ebbea1006
status: experimental
description: Use dir to collect information
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1217/T1217.md
author: frack113
date: 2021/12/13
logsource:
    category: process_creation
    product: windows
detection:
    dir:
        CommandLine|contains|all:
            - 'dir '
            - ' /s'
            - ' /b'
    condition: dir
falsepositives:
    - unknown
level: low
tags:
    - attack.discovery
    - attack.t1217
```
