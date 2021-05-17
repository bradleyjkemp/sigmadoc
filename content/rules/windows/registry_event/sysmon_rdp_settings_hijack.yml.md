---
title: "RDP Sensitive Settings Changed"
aliases:
  - "/rule/171b67e1-74b4-460e-8d55-b331f3e32d67"

tags:
  - attack.defense_evasion
  - attack.t1112





level: high



date: Wed, 3 Apr 2019 14:16:25 +0200


---

Detects changes to RDP terminal service sensitive settings

<!--more-->


## Known false-positives

* unknown



## References

* https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html


## Raw rule
```yaml
title: RDP Sensitive Settings Changed
id: 171b67e1-74b4-460e-8d55-b331f3e32d67
description: Detects changes to RDP terminal service sensitive settings
references:
    - https://blog.menasec.net/2019/02/threat-hunting-rdp-hijacking-via.html
date: 2019/04/03
modified: 2020/09/06
author: Samir Bousseaden
logsource:
    category: registry_event
    product: windows
detection:
    selection_reg:
        TargetObject:
            - '*\services\TermService\Parameters\ServiceDll*'
            - '*\Control\Terminal Server\fSingleSessionPerUser*'
            - '*\Control\Terminal Server\fDenyTSConnections*'
    condition: selection_reg
tags:
    - attack.defense_evasion
    - attack.t1112
falsepositives:
    - unknown
level: high

```
