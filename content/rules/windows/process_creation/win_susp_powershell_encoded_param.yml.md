---
title: "PowerShell Encoded Character Syntax"
aliases:
  - "/rule/e312efd0-35a1-407f-8439-b8d434b438a6"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086
  - attack.defense_evasion
  - attack.t1027



date: Thu, 9 Jul 2020 08:52:32 +0200


---

Detects suspicious encoded character syntax often used for defense evasion

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/0gtweet/status/1281103918693482496


## Raw rule
```yaml
title: PowerShell Encoded Character Syntax
id: e312efd0-35a1-407f-8439-b8d434b438a6
status: experimental
description: Detects suspicious encoded character syntax often used for defense evasion
references:
    - https://twitter.com/0gtweet/status/1281103918693482496
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086      # an old one
    - attack.defense_evasion
    - attack.t1027
author: Florian Roth
date: 2020/07/09
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: '(WCHAR)0x'
    condition: selection
falsepositives:
    - Unknown
level: high

```