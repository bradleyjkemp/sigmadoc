---
title: "TAIDOOR RAT DLL Load"
aliases:
  - "/rule/d1aa3382-abab-446f-96ea-4de52908210b"

tags:
  - attack.execution
  - attack.t1055
  - attack.t1055.001



date: Tue, 4 Aug 2020 14:31:20 +0200


---

Detects specific process characteristics of Chinese TAIDOOR RAT malware load

<!--more-->


## Known false-positives

* Unknown



## References

* https://us-cert.cisa.gov/ncas/analysis-reports/ar20-216a


## Raw rule
```yaml
title: TAIDOOR RAT DLL Load
id: d1aa3382-abab-446f-96ea-4de52908210b
status: experimental
description: Detects specific process characteristics of Chinese TAIDOOR RAT malware load
references:
    - https://us-cert.cisa.gov/ncas/analysis-reports/ar20-216a
author: Florian Roth
date: 2020/07/30
tags:
    - attack.execution
    - attack.t1055 # an old one
    - attack.t1055.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'dll,MyStart'
            - 'dll MyStart'
    selection2a:
        CommandLine|endswith:
            - ' MyStart'
    selection2b:
        CommandLine|contains:
            - 'rundll32.exe' 
    condition: selection1 or ( selection2a and selection2b )
falsepositives:
    - Unknown
level: critical

```
