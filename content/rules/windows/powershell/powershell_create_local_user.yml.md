---
title: "PowerShell Create Local User"
aliases:
  - "/rule/243de76f-4725-4f2e-8225-a8a69b15ad61"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086
  - attack.persistence
  - attack.t1136.001
  - attack.t1136



status: experimental



level: medium



date: Sat, 11 Apr 2020 02:51:05 -0600


---

Detects creation of a local user via PowerShell

<!--more-->


## Known false-positives

* Legitimate user creation



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136/T1136.md


## Raw rule
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
    - attack.t1086  # an old one
    - attack.persistence
    - attack.t1136.001
    - attack.t1136  # an old one    
author: '@ROxPinTeddy'
date: 2020/04/11
modified: 2020/08/24
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        Message|contains:
            - 'New-LocalUser'
    condition: selection
falsepositives:
    - Legitimate user creation
level: medium

```
