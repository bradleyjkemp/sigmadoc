---
title: "Defrag Deactivation"
aliases:
  - "/rule/958d81aa-8566-4cea-a565-59ccd4df27b0"

tags:
  - attack.persistence
  - attack.s0111





level: medium



date: Sat, 10 Mar 2018 15:49:50 +0100


---

Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group

<!--more-->


## Known false-positives

* Unknown



## References

* https://securelist.com/apt-slingshot/84312/


## Raw rule
```yaml
action: global
title: Defrag Deactivation
id: 958d81aa-8566-4cea-a565-59ccd4df27b0
author: Florian Roth
date: 2019/03/04
modified: 2020/08/27
description: Detects the deactivation of the Scheduled defragmentation task as seen by Slingshot APT group
references:
    - https://securelist.com/apt-slingshot/84312/
tags:
    - attack.persistence
    - attack.s0111
detection:
    condition: 1 of them
falsepositives:
    - Unknown
level: medium
---
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*schtasks* /delete *Defrag\ScheduledDefrag*'
---
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Audit Other Object Access Events > Success'
detection:
    selection2:
        EventID: 4701
        TaskName: '\Microsoft\Windows\Defrag\ScheduledDefrag'

```
