---
title: "Remote Registry Management Using Reg Utility"
aliases:
  - "/rule/68fcba0d-73a5-475e-a915-e8b4c576827e"

tags:
  - attack.defense_evasion
  - attack.t1112
  - attack.discovery
  - attack.t1012
  - attack.credential_access
  - attack.t1552.002
  - attack.s0075



status: experimental



level: medium



date: Mon, 4 Nov 2019 04:26:34 +0300


---

Remote registry management using REG utility from non-admin workstation

<!--more-->


## Known false-positives

* Legitimate usage of remote registry management by administrator



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule
```yaml
title: Remote Registry Management Using Reg Utility
id: 68fcba0d-73a5-475e-a915-e8b4c576827e
description: Remote registry management using REG utility from non-admin workstation
author: Teymur Kheirkhabarov, oscd.community
date: 2019/10/22
modified: 2020/08/23
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.defense_evasion
    - attack.t1112
    - attack.discovery
    - attack.t1012
    - attack.credential_access
    - attack.t1552.002
    - attack.s0075
logsource:
    product: windows
    service: security
detection:
    selection_1:
        EventID: 5145
        RelativeTargetName|contains: '\winreg'
    selection_2:
        IpAddress: '%Admins_Workstations%'
    condition: selection_1 and not selection_2
falsepositives:
    - Legitimate usage of remote registry management by administrator
level: medium
status: experimental

```
