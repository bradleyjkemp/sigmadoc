---
title: "Application Whitelisting Bypass via Dxcap.exe"
aliases:
  - "/rule/60f16a96-db70-42eb-8f76-16763e333590"

tags:
  - attack.defense_evasion
  - attack.t1218
  - attack.execution



status: experimental



level: medium



date: Sat, 26 Oct 2019 08:16:08 +0200


---

Detects execution of of Dxcap.exe

<!--more-->


## Known false-positives

* Legitimate execution of dxcap.exe by legitimate user



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml
* https://twitter.com/harr0ey/status/992008180904419328


## Raw rule
```yaml
title: Application Whitelisting Bypass via Dxcap.exe
id: 60f16a96-db70-42eb-8f76-16763e333590
status: experimental
description: Detects execution of of Dxcap.exe
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml
    - https://twitter.com/harr0ey/status/992008180904419328
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.t1218
    - attack.execution # an old one
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dxcap.exe'
        CommandLine|contains|all:
            - '-c'
            - '.exe'
    condition: selection
falsepositives:
    - Legitimate execution of dxcap.exe by legitimate user

```
