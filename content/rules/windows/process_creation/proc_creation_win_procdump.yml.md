---
title: "Procdump Usage"
aliases:
  - "/rule/2e65275c-8288-4ab4-aeb7-6274f58b6b20"
ruleid: 2e65275c-8288-4ab4-aeb7-6274f58b6b20

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1003.001



status: experimental





date: Mon, 16 Aug 2021 13:55:00 +0200


---

Detects uses of the SysInternals Procdump utility

<!--more-->


## Known false-positives

* Legitimate use of procdump by a developer or administrator



## References

* Internal Research


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_procdump.yml))
```yaml
title: Procdump Usage
id: 2e65275c-8288-4ab4-aeb7-6274f58b6b20
description: Detects uses of the SysInternals Procdump utility
status: experimental
references:
    - Internal Research
author: Florian Roth
date: 2021/08/16
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith:
            - '\procdump.exe'
            - '\procdump64.exe'
    selection2:
        CommandLine|contains|all:
            - ' -ma '
            - '.exe'
    condition: selection1 or selection2
falsepositives:
    - Legitimate use of procdump by a developer or administrator
level: medium

```
