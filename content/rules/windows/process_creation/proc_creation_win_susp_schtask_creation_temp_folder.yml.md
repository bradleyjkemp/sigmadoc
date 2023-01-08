---
title: "Suspicious Scheduled Task Creation Involving Temp Folder"
aliases:
  - "/rule/39019a4e-317f-4ce3-ae63-309a8c6b53c5"
ruleid: 39019a4e-317f-4ce3-ae63-309a8c6b53c5

tags:
  - attack.execution
  - attack.persistence
  - attack.t1053.005



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the creation of scheduled tasks that involves a temporary folder and runs only once

<!--more-->


## Known false-positives

* Administrative activity
* Software installation



## References

* https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_schtask_creation_temp_folder.yml))
```yaml
title: Suspicious Scheduled Task Creation Involving Temp Folder
id: 39019a4e-317f-4ce3-ae63-309a8c6b53c5
status: experimental
description: Detects the creation of scheduled tasks that involves a temporary folder and runs only once
author: Florian Roth
date: 2021/03/11
references:
    - https://discuss.elastic.co/t/detection-and-response-for-hafnium-activity/266289/3
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains|all: 
            - ' /create '
            - ' /sc once '
            - '\Temp\'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
    - attack.execution
    - attack.persistence
    - attack.t1053.005
falsepositives:
    - Administrative activity
    - Software installation
level: high

```
