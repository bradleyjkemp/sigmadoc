---
title: "Suspicious Process Start Locations"
aliases:
  - "/rule/15b75071-74cc-47e0-b4c6-b43744a62a2b"

tags:
  - attack.defense_evasion
  - attack.t1036
  - car.2013-05-002



status: experimental



level: medium



date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects suspicious process run from unusual locations

<!--more-->


## Known false-positives

* False positives depend on scripts and administrative tools used in the monitored environment



## References

* https://car.mitre.org/wiki/CAR-2013-05-002


## Raw rule
```yaml
title: Suspicious Process Start Locations
id: 15b75071-74cc-47e0-b4c6-b43744a62a2b
description: Detects suspicious process run from unusual locations
status: experimental
references:
    - https://car.mitre.org/wiki/CAR-2013-05-002
author: juju4
date: 2019/01/16
tags:
    - attack.defense_evasion
    - attack.t1036
    - car.2013-05-002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image:
            - '*:\RECYCLER\\*'
            - '*:\SystemVolumeInformation\\*'
            - 'C:\\Windows\\Tasks\\*'
            - 'C:\\Windows\\debug\\*'
            - 'C:\\Windows\\fonts\\*'
            - 'C:\\Windows\\help\\*'
            - 'C:\\Windows\\drivers\\*'
            - 'C:\\Windows\\addins\\*'
            - 'C:\\Windows\\cursors\\*'
            - 'C:\\Windows\\system32\tasks\\*'

    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: medium

```
