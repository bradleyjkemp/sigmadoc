---
title: "Suspicious Add Scheduled Task Parent"
aliases:
  - "/rule/9494479d-d994-40bf-a8b1-eea890237021"


tags:
  - attack.execution
  - attack.t1053.005



status: experimental





date: Wed, 23 Feb 2022 23:25:20 +0100


---

Detects suspicious scheduled task creations from a parent stored in a temporary folder

<!--more-->


## Known false-positives

* Software installers that run from temporary folders and also install scheduled tasks



## References

* https://app.any.run/tasks/649e7b46-9bec-4d05-98a5-dfa9a13eaae5/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_schtasks_parent.yml))
```yaml
title: Suspicious Add Scheduled Task Parent
id: 9494479d-d994-40bf-a8b1-eea890237021
description: Detects suspicious scheduled task creations from a parent stored in a temporary folder
status: experimental
references:
   - https://app.any.run/tasks/649e7b46-9bec-4d05-98a5-dfa9a13eaae5/
tags:
   - attack.execution
   - attack.t1053.005 
author: Florian Roth
date: 2022/02/23
modified: 2022/02/24
logsource:
   product: windows
   category: process_creation
detection:
   selection:
      Image|endswith: 'schtasks.exe'
      CommandLine|contains: '/Create '
      ParentImage|contains:
         - '\AppData\Local\'
         - '\AppData\Roaming\'
         - '\Temporary Internet'
         - '\Users\Public\'
   filter:
      CommandLine|contains:
         - 'update_task.xml'
         - 'unattended.ini'
   condition: selection and not 1 of filter*
falsepositives:
   - Software installers that run from temporary folders and also install scheduled tasks
level: medium

```
