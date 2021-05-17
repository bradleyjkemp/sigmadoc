---
title: "Suspicious RASdial Activity"
aliases:
  - "/rule/6bba49bf-7f8c-47d6-a1bb-6b4dece4640e"

tags:
  - attack.defense_evasion
  - attack.execution
  - attack.t1059
  - attack.t1064



status: experimental



level: medium



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious process related to rasdial.exe

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://twitter.com/subTee/status/891298217907830785


## Raw rule
```yaml
title: Suspicious RASdial Activity
id: 6bba49bf-7f8c-47d6-a1bb-6b4dece4640e
description: Detects suspicious process related to rasdial.exe
status: experimental
references:
    - https://twitter.com/subTee/status/891298217907830785
author: juju4
date: 2019/01/16
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1059
    - attack.t1064      # an old one 
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - rasdial.exe
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```
