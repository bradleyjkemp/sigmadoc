---
title: "Tamper Windows Defender"
aliases:
  - "/rule/ec19ebab-72dc-40e1-9728-4c0b805d722c"
ruleid: ec19ebab-72dc-40e1-9728-4c0b805d722c

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Attempting to disable scheduled scanning and other parts of windows defender atp.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_classic/posh_pc_tamper_with_windows_defender.yml))
```yaml
title: Tamper Windows Defender
id: ec19ebab-72dc-40e1-9728-4c0b805d722c
description: Attempting to disable scheduled scanning and other parts of windows defender atp.
status: experimental
tags:
    - attack.defense_evasion
    - attack.t1562.001
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md
author: frack113
date: 2021/06/07
modified: 2021/10/16
falsepositives:
    - Unknown
level: high
logsource:
    product: windows
    category: ps_classic_provider_start
    definition: fields have to be extract from event
detection:
    tamper_ps_action:
        HostApplication|contains: 'Set-MpPreference'
    tamper_ps_option:
        HostApplication|contains:
            - '-DisableRealtimeMonitoring 1'
            - '-DisableBehaviorMonitoring 1'
            - '-DisableScriptScanning 1'
            - '-DisableBlockAtFirstSeen 1'
    condition: tamper_ps_action and  tamper_ps_option

```
