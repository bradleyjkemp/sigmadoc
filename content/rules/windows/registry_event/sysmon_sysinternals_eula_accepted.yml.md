---
title: "Usage of Sysinternals Tools"
aliases:
  - "/rule/25ffa65d-76d8-4da5-a832-3f2b0136e133"



status: experimental



level: low



date: Tue, 28 Aug 2018 17:36:22 +0200


---

Detects the usage of Sysinternals Tools due to accepteula key being added to Registry

<!--more-->


## Known false-positives

* Legitimate use of SysInternals tools
* Programs that use the same Registry Key



## References

* https://twitter.com/Moti_B/status/1008587936735035392


## Raw rule
```yaml
action: global
title: Usage of Sysinternals Tools
id: 25ffa65d-76d8-4da5-a832-3f2b0136e133
status: experimental
description: Detects the usage of Sysinternals Tools due to accepteula key being added to Registry
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
date: 2017/08/28
author: Markus Neis
falsepositives:
    - Legitimate use of SysInternals tools
    - Programs that use the same Registry Key
level: low
---
logsource:
    product: windows
    category: registry_event
detection:
    selection1:
        TargetObject: '*\EulaAccepted'
    condition: 1 of them
---
logsource:
    category: process_creation
    product: windows
detection:
    selection2:
        CommandLine: '* -accepteula*'
    condition: 1 of them
```
