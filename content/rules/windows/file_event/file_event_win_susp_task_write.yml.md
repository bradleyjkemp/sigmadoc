---
title: "Suspicious Scheduled Task Write to System32 Tasks"
aliases:
  - "/rule/80e1f67a-4596-4351-98f5-a9c3efabac95"
ruleid: 80e1f67a-4596-4351-98f5-a9c3efabac95

tags:
  - attack.persistence
  - attack.execution
  - attack.t1053



status: experimental





date: Tue, 16 Nov 2021 17:30:47 +0100


---

Detects the creation of tasks from processes executed from suspicious locations

<!--more-->


## Known false-positives

* Unknown



## References

* Internal Research


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/file_event/file_event_win_susp_task_write.yml))
```yaml
title: Suspicious Scheduled Task Write to System32 Tasks
id: 80e1f67a-4596-4351-98f5-a9c3efabac95
status: experimental
description: Detects the creation of tasks from processes executed from suspicious locations
references:
    - Internal Research
author: Florian Roth
date: 2021/11/16
modified: 2022/01/12
tags:
    - attack.persistence
    - attack.execution
    - attack.t1053 
logsource:
    product: windows
    category: file_event
detection:
    selection:
        TargetFilename|contains: '\Windows\System32\Tasks'
        Image|contains: 
            - '\AppData\'
            - 'C:\PerfLogs'
            - '\Windows\System32\config\systemprofile'
    condition: selection
falsepositives:
    - Unknown
level: high

```
