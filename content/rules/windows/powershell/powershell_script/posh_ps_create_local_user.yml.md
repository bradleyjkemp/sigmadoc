---
title: "PowerShell Create Local User"
aliases:
  - "/rule/243de76f-4725-4f2e-8225-a8a69b15ad61"
ruleid: 243de76f-4725-4f2e-8225-a8a69b15ad61

tags:
  - attack.execution
  - attack.t1059.001
  - attack.persistence
  - attack.t1136.001



status: experimental





date: Sat, 11 Apr 2020 02:51:05 -0600


---

Detects creation of a local user via PowerShell

<!--more-->


## Known false-positives

* Legitimate user creation



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_create_local_user.yml))
```yaml
title: PowerShell Create Local User
id: 243de76f-4725-4f2e-8225-a8a69b15ad61
status: experimental
description: Detects creation of a local user via PowerShell
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md
tags:
    - attack.execution
    - attack.t1059.001
    - attack.persistence
    - attack.t1136.001  
author: '@ROxPinTeddy'
date: 2020/04/11
modified: 2021/10/16
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains: 'New-LocalUser'
    condition: selection
falsepositives:
    - Legitimate user creation
level: medium

```
