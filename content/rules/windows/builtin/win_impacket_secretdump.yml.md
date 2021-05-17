---
title: "Possible Impacket SecretDump Remote Activity"
aliases:
  - "/rule/252902e3-5830-4cf6-bf21-c22083dfd5cf"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.003





level: high



date: Wed, 3 Apr 2019 15:18:42 +0200


---

Detect AD credential dumping using impacket secretdump HKTL

<!--more-->


## Known false-positives

* pentesting



## References

* https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html


## Raw rule
```yaml
title: Possible Impacket SecretDump Remote Activity
id: 252902e3-5830-4cf6-bf21-c22083dfd5cf
description: Detect AD credential dumping using impacket secretdump HKTL
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://blog.menasec.net/2019/02/threat-huting-10-impacketsecretdump.html
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.003
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\ADMIN$
        RelativeTargetName: 'SYSTEM32\\*.tmp'
    condition: selection
falsepositives:
    - pentesting
level: high

```
