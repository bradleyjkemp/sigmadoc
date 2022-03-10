---
title: "Uninstall Crowdstrike Falcon"
aliases:
  - "/rule/f0f7be61-9cf5-43be-9836-99d6ef448a18"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Wed, 7 Jul 2021 15:43:55 +0200


---

Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon

<!--more-->


## Known false-positives

* Uninstall by admin



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_uninstall_crowdstrike_falcon.yml))
```yaml
title: Uninstall Crowdstrike Falcon
id: f0f7be61-9cf5-43be-9836-99d6ef448a18
status: experimental
author: frack113
date: 2021/07/12
description: Adversaries may disable security tools to avoid possible detection of their tools and activities by uninstalling Crowdstrike Falcon
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - '\WindowsSensor.exe'
            - ' /uninstall'
            - ' /quiet'
    condition: selection 
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Uninstall by admin
level: medium

```
