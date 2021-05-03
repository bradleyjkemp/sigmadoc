---
title: "Persistence and Execution at Scale via GPO Scheduled Task"
aliases:
  - "/rule/a8f29a7b-b137-4446-80a0-b804272f3da2"

tags:
  - attack.persistence
  - attack.lateral_movement
  - attack.t1053
  - attack.t1053.005



date: Wed, 3 Apr 2019 15:36:24 +0200


---

Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale

<!--more-->


## Known false-positives

* if the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduledtasks



## References

* https://twitter.com/menasec1/status/1106899890377052160
* https://www.secureworks.com/blog/ransomware-as-a-distraction


## Raw rule
```yaml
title: Persistence and Execution at Scale via GPO Scheduled Task
id: a8f29a7b-b137-4446-80a0-b804272f3da2
description: Detect lateral movement using GPO scheduled task, usually used to deploy ransomware at scale
author: Samir Bousseaden
date: 2019/04/03
references:
    - https://twitter.com/menasec1/status/1106899890377052160
    - https://www.secureworks.com/blog/ransomware-as-a-distraction
tags:
    - attack.persistence
    - attack.lateral_movement
    - attack.t1053          # an old one
    - attack.t1053.005
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit Detailed File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5145
        ShareName: \\*\SYSVOL
        RelativeTargetName: '*ScheduledTasks.xml'
        Accesses: '*WriteData*'
    condition: selection
falsepositives:
    - if the source IP is not localhost then it's super suspicious, better to monitor both local and remote changes to GPO scheduledtasks
level: high

```
