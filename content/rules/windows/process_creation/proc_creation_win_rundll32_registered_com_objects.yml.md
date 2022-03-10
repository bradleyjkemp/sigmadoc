---
title: "Rundll32 Registered COM Objects"
aliases:
  - "/rule/f1edd233-30b5-4823-9e6a-c4171b24d316"


tags:
  - attack.privilege_escalation
  - attack.persistence
  - attack.t1546.015



status: experimental





date: Sun, 13 Feb 2022 11:04:00 +0100


---

load malicious registered COM objects

<!--more-->


## Known false-positives

* legitimate use



## References

* https://nasbench.medium.com/a-deep-dive-into-rundll32-exe-642344b41e90
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.015/T1546.015.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_rundll32_registered_com_objects.yml))
```yaml
title: Rundll32 Registered COM Objects
id: f1edd233-30b5-4823-9e6a-c4171b24d316
status: experimental
description: load malicious registered COM objects 
references:
    - https://nasbench.medium.com/a-deep-dive-into-rundll32-exe-642344b41e90
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.015/T1546.015.md
author: frack113
date: 2022/02/13
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \rundll32.exe
        CommandLine|contains:
            - '-sta '
            - '–localserver '
        CommandLine|contains|all:
            - '{'
            - '}'
    condition: selection
falsepositives:
    - legitimate use
level: high
tags:
    - attack.privilege_escalation
    - attack.persistence
    - attack.t1546.015

```
