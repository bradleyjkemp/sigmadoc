---
title: "Scheduled Task Deletion"
aliases:
  - "/rule/4f86b304-3e02-40e3-aa5d-e88a167c9617"


tags:
  - attack.execution
  - attack.privilege_escalation
  - car.2013-08-001
  - attack.t1053.005



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects scheduled task deletion events. Scheduled tasks are likely to be deleted if not used for persistence. Malicious Software often creates tasks directly under the root node e.g. \TASKNAME

<!--more-->


## Known false-positives

* Software installation



## References

* https://twitter.com/matthewdunwoody/status/1352356685982146562
* https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4699


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_scheduled_task_deletion.yml))
```yaml
title: Scheduled Task Deletion
id: 4f86b304-3e02-40e3-aa5d-e88a167c9617 
description: Detects scheduled task deletion events. Scheduled tasks are likely to be deleted if not used for persistence. Malicious Software often creates tasks directly under the root node e.g. \TASKNAME
status: experimental
author: David Strassegger
date: 2021/01/22
tags:
    - attack.execution
    - attack.privilege_escalation
    - car.2013-08-001
    - attack.t1053.005
references:
    - https://twitter.com/matthewdunwoody/status/1352356685982146562
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4699
logsource:
    product: windows
    service: security
    definition: 'The Advanced Audit Policy setting Object Access > Audit Other Object Access Events has to be configured to allow this detection. We also recommend extracting the Command field from the embedded XML in the event data.'
detection:
    selection:
        EventID: 4699
    condition: selection
falsepositives:
    - Software installation
level: medium

```