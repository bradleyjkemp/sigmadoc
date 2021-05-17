---
title: "OpenWith.exe Executes Specified Binary"
aliases:
  - "/rule/cec8e918-30f7-4e2d-9bfa-a59cc97ae60f"

tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.execution



status: experimental



level: high



date: Wed, 23 Oct 2019 13:00:21 +0200


---

The OpenWith.exe executes other binary

<!--more-->


## Known false-positives

* Legitimate use of OpenWith.exe by legitimate user



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml
* https://twitter.com/harr0ey/status/991670870384021504


## Raw rule
```yaml
title: OpenWith.exe Executes Specified Binary
id: cec8e918-30f7-4e2d-9bfa-a59cc97ae60f
status: experimental
description: The OpenWith.exe executes other binary
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OSBinaries/Openwith.yml
    - https://twitter.com/harr0ey/status/991670870384021504
author: Beyu Denis, oscd.community (rule), @harr0ey (idea)
date: 2019/10/12
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.execution      # an old one
level: high
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\OpenWith.exe'
        CommandLine|contains: '/c'
    condition: selection
falsepositives:
    - Legitimate use of OpenWith.exe by legitimate user

```
