---
title: "Renamed PowerShell"
aliases:
  - "/rule/d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20"
ruleid: d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20

tags:
  - car.2013-05-009
  - attack.defense_evasion
  - attack.t1036.003



status: test





date: Thu, 22 Aug 2019 14:22:36 +0200


---

Detects the execution of a renamed PowerShell often used by attackers or malware

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/christophetd/status/1164506034720952320


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_renamed_powershell.yml))
```yaml
title: Renamed PowerShell
id: d178a2d7-129a-4ba4-8ee6-d6e1fecd5d20
status: test
description: Detects the execution of a renamed PowerShell often used by attackers or malware
references:
    - https://twitter.com/christophetd/status/1164506034720952320
author: Florian Roth, frack113
date: 2019/08/22
modified: 2021/07/03
tags:
    - car.2013-05-009
    - attack.defense_evasion
    - attack.t1036.003
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Description|startswith:
            - 'Windows PowerShell'
            - 'pwsh'
        Company: 'Microsoft Corporation'
    filter:
        Image|endswith:
            - '\powershell.exe'
            - '\powershell_ise.exe'
            - '\pwsh.exe'
    condition: selection and not filter
falsepositives:
    - Unknown
level: critical

```
