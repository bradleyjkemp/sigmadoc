---
title: "Copy from Admin Share"
aliases:
  - "/rule/855bc8b5-2ae8-402e-a9ed-b889e6df1900"

tags:
  - attack.lateral_movement
  - attack.t1021.002
  - attack.command_and_control
  - attack.t1105
  - attack.s0106
  - attack.t1077



date: Mon, 30 Dec 2019 14:25:43 +0100


---

Detects a suspicious copy command from a remote C$ or ADMIN$ share

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://twitter.com/SBousseaden/status/1211636381086339073


## Raw rule
```yaml
title: Copy from Admin Share
id: 855bc8b5-2ae8-402e-a9ed-b889e6df1900
status: experimental
description: Detects a suspicious copy command from a remote C$ or ADMIN$ share
references:
    - https://twitter.com/SBousseaden/status/1211636381086339073
author: Florian Roth
date: 2019/12/30
modified: 2020/09/05
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.command_and_control 
    - attack.t1105
    - attack.s0106
    - attack.t1077      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'copy *\c$'
            - 'copy *\ADMIN$'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: high

```
