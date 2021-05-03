---
title: "Regsvr32 Flags Anomaly"
aliases:
  - "/rule/b236190c-1c61-41e9-84b3-3fe03f6d76b0"

tags:
  - attack.defense_evasion
  - attack.t1218.010
  - attack.t1117



date: Mon, 13 Jul 2020 11:59:44 +0200


---

Detects a flag anomaly in which regsvr32.exe uses a /i flag without using a /n flag at the same time

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/sbousseaden/status/1282441816986484737?s=12


## Raw rule
```yaml
title: Regsvr32 Flags Anomaly
id: b236190c-1c61-41e9-84b3-3fe03f6d76b0
status: experimental
description: Detects a flag anomaly in which regsvr32.exe uses a /i flag without using a /n flag at the same time
author: Florian Roth
date: 2019/07/13
references:
    - https://twitter.com/sbousseaden/status/1282441816986484737?s=12
tags:
    - attack.defense_evasion
    - attack.t1218.010
    - attack.t1117      # an old one 
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains: ' /i:'
    filter:
        CommandLine|contains: ' /n '
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```