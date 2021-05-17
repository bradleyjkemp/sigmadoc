---
title: "Judgement Panda Exfil Activity"
aliases:
  - "/rule/03e2746e-2b31-42f1-ab7a-eb39365b2422"

tags:
  - attack.lateral_movement
  - attack.g0010
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001
  - attack.exfiltration
  - attack.t1002
  - attack.t1560.001





level: critical



date: Thu, 21 Feb 2019 09:18:36 +0100


---

Detects Judgement Panda activity as described in Global Threat Report 2019 by Crowdstrike

<!--more-->


## Known false-positives

* unknown



## References

* https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/


## Raw rule
```yaml
title: Judgement Panda Exfil Activity
id: 03e2746e-2b31-42f1-ab7a-eb39365b2422
description: Detects Judgement Panda activity as described in Global Threat Report 2019 by Crowdstrike
references:
    - https://www.crowdstrike.com/resources/reports/2019-crowdstrike-global-threat-report/
author: Florian Roth
date: 2019/02/21
modified: 2020/08/27
tags:
    - attack.lateral_movement
    - attack.g0010
    - attack.credential_access
    - attack.t1003 # an old one
    - attack.t1003.001
    - attack.exfiltration
    - attack.t1002 # an old one
    - attack.t1560.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*\ldifde.exe -f -n *'
            - '*\7za.exe a 1.7z *'
            - '* eprod.ldf'
            - '*\aaaa\procdump64.exe*'
            - '*\aaaa\netsess.exe*'
            - '*\aaaa\7za.exe*'
            - '*copy .\1.7z \\*'
            - '*copy \\client\c$\aaaa\\*'
    selection2:
        Image: C:\Users\Public\7za.exe
    condition: selection1 or selection2
falsepositives:
    - unknown
level: critical

```
