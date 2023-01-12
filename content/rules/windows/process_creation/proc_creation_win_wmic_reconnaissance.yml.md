---
title: "Suspicious WMI Reconnaissance"
aliases:
  - "/rule/221b251a-357a-49a9-920a-271802777cc0"
ruleid: 221b251a-357a-49a9-920a-271802777cc0

tags:
  - attack.execution
  - attack.t1047



status: experimental





date: Sat, 1 Jan 2022 08:42:40 +0100


---

An adversary might use WMI to list Processes running on the compromised host or list installed Software hotfix and patches.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wmic


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_wmic_reconnaissance.yml))
```yaml
title: Suspicious WMI Reconnaissance
id: 221b251a-357a-49a9-920a-271802777cc0
status: experimental
description: An adversary might use WMI to list Processes running on the compromised host or list installed Software hotfix and patches.
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1047/T1047.md
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/wmic
date: 2022/01/01
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \WMIC.exe
        CommandLine|contains: 
            - process 
            - qfe
    filter:
        CommandLine|contains|all: #rule id 526be59f-a573-4eea-b5f7-f0973207634d for `wmic process call create #{process_to_execute}` 
            - call
            - create 
    condition: selection and not filter
falsepositives:
    - Unknown
level: medium
tags:
    - attack.execution
    - attack.t1047

```