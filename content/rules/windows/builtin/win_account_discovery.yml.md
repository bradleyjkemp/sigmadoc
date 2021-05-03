---
title: "AD Privileged Users or Groups Reconnaissance"
aliases:
  - "/rule/35ba1d85-724d-42a3-889f-2e2362bcaf23"

tags:
  - attack.discovery
  - attack.t1087
  - attack.t1087.002



date: Wed, 3 Apr 2019 14:41:11 +0200


---

Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs

<!--more-->


## Known false-positives

* if source account name is not an admin then its super suspicious



## References

* https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html


## Raw rule
```yaml
title: AD Privileged Users or Groups Reconnaissance
id: 35ba1d85-724d-42a3-889f-2e2362bcaf23
description: Detect priv users or groups recon based on 4661 eventid and known privileged users or groups SIDs
references:
    - https://blog.menasec.net/2019/02/threat-hunting-5-detecting-enumeration.html
tags:
    - attack.discovery
    - attack.t1087          # an old one
    - attack.t1087.002
status: experimental
author: Samir Bousseaden
date: 2019/04/03
modified: 2020/08/23
logsource:
    product: windows
    service: security
    definition: 'Requirements: enable Object Access SAM on your Domain Controllers'
detection:
    selection:
        EventID: 4661
        ObjectType:
        - 'SAM_USER'
        - 'SAM_GROUP'
        ObjectName:
         - '*-512'
         - '*-502'
         - '*-500'
         - '*-505'
         - '*-519'
         - '*-520'
         - '*-544'
         - '*-551'
         - '*-555'
         - '*admin*'
    condition: selection
falsepositives:
    - if source account name is not an admin then its super suspicious
level: high

```
