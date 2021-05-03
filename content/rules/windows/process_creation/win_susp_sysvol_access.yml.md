---
title: "Suspicious SYSVOL Domain Group Policy Access"
aliases:
  - "/rule/05f3c945-dcc8-4393-9f3d-af65077a8f86"

tags:
  - attack.credential_access
  - attack.t1552.006
  - attack.t1003



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects Access to Domain Group Policies stored in SYSVOL

<!--more-->


## Known false-positives

* administrative activity



## References

* https://adsecurity.org/?p=2288
* https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100


## Raw rule
```yaml
title: Suspicious SYSVOL Domain Group Policy Access
id: 05f3c945-dcc8-4393-9f3d-af65077a8f86
status: experimental
description: Detects Access to Domain Group Policies stored in SYSVOL
references:
    - https://adsecurity.org/?p=2288
    - https://www.hybrid-analysis.com/sample/f2943f5e45befa52fb12748ca7171d30096e1d4fc3c365561497c618341299d5?environmentId=100
author: Markus Neis
date: 2018/04/09
modified: 2020/08/28
tags:
    - attack.credential_access
    - attack.t1552.006
    - attack.t1003      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '*\SYSVOL\\*\policies\\*'
    condition: selection
falsepositives:
    - administrative activity
level: medium

```
