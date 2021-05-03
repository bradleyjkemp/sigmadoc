---
title: "Winnti Pipemon Characteristics"
aliases:
  - "/rule/73d70463-75c9-4258-92c6-17500fe972f2"

tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.t1073
  - attack.g0044



date: Thu, 30 Jul 2020 18:55:47 +0200


---

Detects specific process characteristics of Winnti Pipemon malware reported by ESET

<!--more-->


## Known false-positives

* Legitimate setups that use similar flags



## References

* https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/


## Raw rule
```yaml
title: Winnti Pipemon Characteristics
id: 73d70463-75c9-4258-92c6-17500fe972f2
status: experimental
description: Detects specific process characteristics of Winnti Pipemon malware reported by ESET
references:
    - https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/
tags:
    - attack.defense_evasion
    - attack.t1574.002
    - attack.t1073  # an old one
    - attack.g0044
author: Florian Roth
date: 2020/07/30
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'setup0.exe -p'
    selection2:
        CommandLine|endswith:    
            - 'setup.exe -x:0'
            - 'setup.exe -x:1'
            - 'setup.exe -x:2'
    condition: 1 of them
falsepositives:
    - Legitimate setups that use similar flags
level: critical

```
