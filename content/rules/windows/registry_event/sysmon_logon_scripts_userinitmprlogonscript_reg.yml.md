---
title: "Logon Scripts (UserInitMprLogonScript) Registry"
aliases:
  - "/rule/9ace0707-b560-49b8-b6ca-5148b42f39fb"

tags:
  - attack.t1037
  - attack.t1037.001
  - attack.persistence
  - attack.lateral_movement



status: experimental



level: high



date: Wed, 1 Jul 2020 10:58:39 +0200


---

Detects creation or execution of UserInitMprLogonScript persistence method

<!--more-->


## Known false-positives

* exclude legitimate logon scripts
* penetration tests, red teaming



## References

* https://attack.mitre.org/techniques/T1037/


## Raw rule
```yaml
title: Logon Scripts (UserInitMprLogonScript) Registry
id: 9ace0707-b560-49b8-b6ca-5148b42f39fb
status: experimental
description: Detects creation or execution of UserInitMprLogonScript persistence method
references:
    - https://attack.mitre.org/techniques/T1037/
tags:
    - attack.t1037 # an old one
    - attack.t1037.001
    - attack.persistence
    - attack.lateral_movement
author: Tom Ueltschi (@c_APT_ure)
date: 2019/01/12
modified: 2020/07/01
logsource:
    category: registry_event
    product: windows
detection:
    create_keywords_reg:
        TargetObject: '*UserInitMprLogonScript*'
    condition: create_keywords_reg
falsepositives:
    - exclude legitimate logon scripts
    - penetration tests, red teaming
level: high
```
