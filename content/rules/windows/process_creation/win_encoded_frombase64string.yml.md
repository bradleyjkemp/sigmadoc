---
title: "Encoded FromBase64String"
aliases:
  - "/rule/fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c"

tags:
  - attack.defense_evasion
  - attack.t1140
  - attack.execution
  - attack.t1059.001
  - attack.t1086



date: Fri, 23 Aug 2019 23:13:23 +0200


---

Detects a base64 encoded FromBase64String keyword in a process command line

<!--more-->


## Known false-positives

* unknown




## Raw rule
```yaml
title: Encoded FromBase64String
id: fdb62a13-9a81-4e5c-a38f-ea93a16f6d7c
status: experimental
description: Detects a base64 encoded FromBase64String keyword in a process command line
author: Florian Roth
date: 2019/08/24
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|base64offset|contains: '::FromBase64String'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - unknown
level: critical

```
