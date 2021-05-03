---
title: "Empire PowerShell UAC Bypass"
aliases:
  - "/rule/3268b746-88d8-4cd3-bffc-30077d02c787"

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1548.002
  - attack.t1088
  - car.2019-04-001



date: Mon, 2 Sep 2019 05:04:44 -0400


---

Detects some Empire PowerShell UAC bypass methods

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
* https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64


## Raw rule
```yaml
title: Empire PowerShell UAC Bypass
id: 3268b746-88d8-4cd3-bffc-30077d02c787
status: experimental
description: Detects some Empire PowerShell UAC bypass methods
references:
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-EventVwrBypass.ps1#L64
    - https://github.com/EmpireProject/Empire/blob/e37fb2eef8ff8f5a0a689f1589f424906fe13055/data/module_source/privesc/Invoke-FodHelperBypass.ps1#L64
author: Ecco
date: 2019/08/30
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -NoP -NonI -w Hidden -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update)*'
            - '* -NoP -NonI -c $x=$((gp HKCU:Software\\Microsoft\\Windows Update).Update);*'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1548.002
    - attack.t1088      # an old one
    - car.2019-04-001
falsepositives:
    - unknown
level: critical

```