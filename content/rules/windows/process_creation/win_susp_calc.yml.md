---
title: "Suspicious Calculator Usage"
aliases:
  - "/rule/737e618a-a410-49b5-bec3-9e55ff7fbc15"

tags:
  - attack.defense_evasion
  - attack.t1036



status: experimental



level: high



---

Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/ItsReallyNick/status/1094080242686312448


## Raw rule
```yaml
title: Suspicious Calculator Usage
id: 737e618a-a410-49b5-bec3-9e55ff7fbc15
description: Detects suspicious use of calc.exe with command line parameters or in a suspicious directory, which is likely caused by some PoC or detection evasion
status: experimental
references:
    - https://twitter.com/ItsReallyNick/status/1094080242686312448
author: Florian Roth
date: 2019/02/09
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine: '*\calc.exe *'
    selection2:
        Image: '*\calc.exe'
    filter2:
        Image: '*\Windows\Sys*'
    condition: selection1 or ( selection2 and not filter2 )
falsepositives:
    - Unknown
level: high

```
