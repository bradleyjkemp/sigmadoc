---
title: "ShimCache Flush"
aliases:
  - "/rule/b0524451-19af-4efa-a46f-562a977f792e"
ruleid: b0524451-19af-4efa-a46f-562a977f792e

tags:
  - attack.defense_evasion
  - attack.t1112



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects actions that clear the local ShimCache and remove forensic evidence

<!--more-->


## Known false-positives

* Unknown



## References

* https://medium.com/@blueteamops/shimcache-flush-89daff28d15e


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_shimcache_flush.yml))
```yaml
title: ShimCache Flush
id: b0524451-19af-4efa-a46f-562a977f792e
status: experimental
description: Detects actions that clear the local ShimCache and remove forensic evidence
references:
    - https://medium.com/@blueteamops/shimcache-flush-89daff28d15e
tags:
    - attack.defense_evasion
    - attack.t1112
author: Florian Roth
date: 2021/02/01
logsource:
    category: process_creation
    product: windows
detection:
    selection1a:
        CommandLine|contains|all:
            - 'rundll32'
            - 'apphelp.dll'
    selection1b:
        CommandLine|contains:
            - 'ShimFlushCache'
            - '#250'
    selection2a:
        CommandLine|contains|all:
            - 'rundll32'
            - 'kernel32.dll'
    selection2b:
        CommandLine|contains:
            - 'BaseFlushAppcompatCache'
            - '#46'
    condition: ( selection1a and selection1b ) or ( selection2a and selection2b )
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: critical

```
