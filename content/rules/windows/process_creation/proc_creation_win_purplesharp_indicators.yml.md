---
title: "PurpleSharp Indicator"
aliases:
  - "/rule/ff23ffbc-3378-435e-992f-0624dcf93ab4"


tags:
  - attack.t1587
  - attack.resource_development



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the execution of the PurpleSharp adversary simulation tool

<!--more-->


## Known false-positives

* Unlikely



## References

* https://github.com/mvelazc0/PurpleSharp


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_purplesharp_indicators.yml))
```yaml
title: PurpleSharp Indicator
id: ff23ffbc-3378-435e-992f-0624dcf93ab4
status: experimental
description: Detects the execution of the PurpleSharp adversary simulation tool
author: Florian Roth
date: 2021/06/18
modified: 2022/01/12
references:
    - https://github.com/mvelazc0/PurpleSharp
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - xyz123456.exe
            - PurpleSharp
    selection2:
        OriginalFileName: 'PurpleSharp.exe'
    condition: selection1 or selection2
falsepositives:
    - Unlikely
level: critical
tags:
    - attack.t1587
    - attack.resource_development
```
