---
title: "Renamed PowerShell"
aliases:
  - "/rule/d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20"

tags:
  - car.2013-05-009
  - attack.defense_evasion
  - attack.t1036
  - attack.t1036.003



date: Thu, 22 Aug 2019 14:22:36 +0200


---

Detects the execution of a renamed PowerShell often used by attackers or malware

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/christophetd/status/1164506034720952320


## Raw rule
```yaml
title: Renamed PowerShell
id: d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20
status: experimental
description: Detects the execution of a renamed PowerShell often used by attackers or malware
references:
    - https://twitter.com/christophetd/status/1164506034720952320
author: Florian Roth
date: 2019/08/22
modified: 2020/09/06
tags:
    - car.2013-05-009
    - attack.defense_evasion
    - attack.t1036 # an old one
    - attack.t1036.003    
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Description: 'Windows PowerShell'
        Company: 'Microsoft Corporation'
    filter:
        Image: 
            - '*\powershell.exe'
            - '*\powershell_ise.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical

```