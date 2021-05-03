---
title: "WMI Spawning Windows PowerShell"
aliases:
  - "/rule/692f0bec-83ba-4d04-af7e-e884a96059b6"

tags:
  - attack.execution
  - attack.t1047
  - attack.t1059.001
  - attack.defense_evasion
  - attack.t1064



date: Wed, 3 Apr 2019 16:56:45 +0200


---

Detects WMI spawning PowerShell

<!--more-->


## Known false-positives

* AppvClient
* CCM



## References

* https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml
* https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e


## Raw rule
```yaml
title: WMI Spawning Windows PowerShell
id: 692f0bec-83ba-4d04-af7e-e884a96059b6
status: experimental
description: Detects WMI spawning PowerShell
references:
    - https://github.com/Neo23x0/sigma/blob/master/rules/windows/process_creation/win_shell_spawn_susp_program.yml
    - https://any.run/report/68bc255f9b0db6a0d30a8f2dadfbee3256acfe12497bf93943bc1eab0735e45e/a2385d6f-34f7-403c-90d3-b1f9d2a90a5e
author: Markus Neis / @Karneades
date: 2019/04/03
modified: 2020/08/29
tags:
    - attack.execution
    - attack.t1047
    - attack.t1059.001
    - attack.defense_evasion # an old one
    - attack.t1064      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\wmiprvse.exe'
        Image:
            - '*\powershell.exe'
    condition: selection
falsepositives:
    - AppvClient
    - CCM
level: high

```
