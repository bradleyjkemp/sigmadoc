---
title: "Stop Or Remove Antivirus Service"
aliases:
  - "/rule/6783aa9e-0dc3-49d4-a94a-8b39c5fd700b"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Wed, 7 Jul 2021 15:43:55 +0200


---

Adversaries may disable security tools to avoid possible detection of their tools and activities by stopping antivirus service

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_service_modification.yml))
```yaml
title: Stop Or Remove Antivirus Service
id: 6783aa9e-0dc3-49d4-a94a-8b39c5fd700b
status: experimental
author: frack113
date: 2021/07/07
modified: 2021/12/02
description: Adversaries may disable security tools to avoid possible detection of their tools and activities by stopping antivirus service
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_action:
        CommandLine|contains:
            - 'Stop-Service '
            - 'Remove-Service '
    selection_product:
        CommandLine|contains:
            - ' McAfeeDLPAgentService'
            - ' Trend Micro Deep Security Manager'
            - ' TMBMServer'
            # Feel free to add more service name         
    condition: all of selection*
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```