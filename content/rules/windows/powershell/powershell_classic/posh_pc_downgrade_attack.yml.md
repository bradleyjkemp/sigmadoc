---
title: "PowerShell Downgrade Attack"
aliases:
  - "/rule/6331d09b-4785-4c13-980f-f96661356249"
ruleid: 6331d09b-4785-4c13-980f-f96661356249

tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1059.001



status: experimental





date: Wed, 22 Mar 2017 11:17:03 +0100


---

Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0

<!--more-->


## Known false-positives

* Penetration Test
* Unknown



## References

* http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_classic/posh_pc_downgrade_attack.yml))
```yaml
title: PowerShell Downgrade Attack
id: 6331d09b-4785-4c13-980f-f96661356249
status: experimental
description: Detects PowerShell downgrade attack by comparing the host versions with the actually used engine version 2.0
references:
    - http://www.leeholmes.com/blog/2017/03/17/detecting-and-preventing-powershell-downgrade-attacks/
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1059.001
author: Florian Roth (rule), Lee Holmes (idea), Harish Segar (improvements)
date: 2017/03/22
modified: 2021/10/16
logsource:
    product: windows
    category: ps_classic_start
    definition: fields have to be extract from event
detection:
    selection:
        EngineVersion|startswith: '2.'
    filter:
        HostVersion|startswith: '2.'
    condition: selection and not filter
falsepositives:
    - Penetration Test
    - Unknown
level: medium

```
