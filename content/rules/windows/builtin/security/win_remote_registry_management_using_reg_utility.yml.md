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



status: test





date: Mon, 4 Nov 2019 04:26:34 +0300


---

Remote registry management using REG utility from non-admin workstation

<!--more-->


## Known false-positives

* Legitimate usage of remote registry management by administrator



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_remote_registry_management_using_reg_utility.yml))
```yaml
title: Remote Registry Management Using Reg Utility
id: 68fcba0d-73a5-475e-a915-e8b4c576827e
status: test
description: Remote registry management using REG utility from non-admin workstation
author: Teymur Kheirkhabarov, oscd.community
references:
  - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
date: 2019/10/22
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection_1:
    EventID: 5145
    RelativeTargetName|contains: '\winreg'
  filter:
    IpAddress: '%Admins_Workstations%'
  condition: selection_1 and not filter
falsepositives:
  - Legitimate usage of remote registry management by administrator
level: medium
tags:
  - attack.defense_evasion
  - attack.t1112
  - attack.discovery
  - attack.t1012
  - attack.credential_access
  - attack.t1552.002
  - attack.s0075

```
