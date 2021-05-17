---
title: "BlueMashroom DLL Load"
aliases:
  - "/rule/bd70d3f8-e60e-4d25-89f0-0b5a9cff20e0"

tags:
  - attack.defense_evasion
  - attack.t1117
  - attack.t1218.010



status: experimental



level: critical



date: Wed, 2 Oct 2019 13:57:14 +0200


---

Detects a suspicious DLL loading from AppData Local path as described in BlueMashroom report

<!--more-->


## Known false-positives

* Unlikely



## References

* https://www.virusbulletin.com/conference/vb2019/abstracts/apt-cases-exploiting-vulnerabilities-region-specific-software


## Raw rule
```yaml
title: BlueMashroom DLL Load
id: bd70d3f8-e60e-4d25-89f0-0b5a9cff20e0
status: experimental
description: Detects a suspicious DLL loading from AppData Local path as described in BlueMashroom report
references:
    - https://www.virusbulletin.com/conference/vb2019/abstracts/apt-cases-exploiting-vulnerabilities-region-specific-software
tags:
    - attack.defense_evasion
    - attack.t1117 # an old one
    - attack.t1218.010
author: Florian Roth
date: 2019/10/02
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\regsvr32*\AppData\Local\\*'
            - '*\AppData\Local\\*,DllEntry*'
    condition: selection
falsepositives:
    - Unlikely
level: critical

```
