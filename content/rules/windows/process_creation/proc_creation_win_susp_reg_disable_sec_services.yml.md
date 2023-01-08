---
title: "Reg Disable Security Service"
aliases:
  - "/rule/5e95028c-5229-4214-afae-d653d573d0ec"
ruleid: 5e95028c-5229-4214-afae-d653d573d0ec

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Wed, 14 Jul 2021 15:52:35 +0200


---

Detects a suspicious reg.exe invocation that looks as if it would disable an important security service

<!--more-->


## Known false-positives

* Unknown
* Other security solution installers



## References

* https://twitter.com/JohnLaTwC/status/1415295021041979392


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_reg_disable_sec_services.yml))
```yaml
title: Reg Disable Security Service
id: 5e95028c-5229-4214-afae-d653d573d0ec
description: Detects a suspicious reg.exe invocation that looks as if it would disable an important security service
status: experimental
references:
    - https://twitter.com/JohnLaTwC/status/1415295021041979392
author: Florian Roth, John Lambert (idea)
date: 2021/07/14
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_reg:
        CommandLine|contains|all:
            - 'reg'
            - 'add'
            - ' /d 4'
            - ' /v Start'
    selection_services:
        CommandLine|contains:
            - '\Sense '
            - '\WinDefend'
            - '\MsMpSvc'
            - '\NisSrv'
            - '\WdBoot '
            - '\WdNisDrv'
            - '\WdNisSvc'
            - '\wscsvc '
            - '\SecurityHealthService'
            - '\wuauserv'
            - '\UsoSvc '
    condition: selection_reg and selection_services
falsepositives:
    - Unknown
    - Other security solution installers
level: high

```
