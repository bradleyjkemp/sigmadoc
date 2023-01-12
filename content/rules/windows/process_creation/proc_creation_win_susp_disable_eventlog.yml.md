---
title: "Disable or Delete Windows Eventlog"
aliases:
  - "/rule/cd1f961e-0b96-436b-b7c6-38da4583ec00"
ruleid: cd1f961e-0b96-436b-b7c6-38da4583ec00

tags:
  - attack.defense_evasion
  - attack.t1562.001
  - attack.t1070.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects command that is used to disable or delete Windows eventlog via logman Windows utility

<!--more-->


## Known false-positives

* Legitimate deactivation by administrative staff
* Installer tools that disable services, e.g. before log collection agent installation



## References

* https://twitter.com/0gtweet/status/1359039665232306183?s=21
* https://ss64.com/nt/logman.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_disable_eventlog.yml))
```yaml
title: Disable or Delete Windows Eventlog
id: cd1f961e-0b96-436b-b7c6-38da4583ec00
status: experimental
description: Detects command that is used to disable or delete Windows eventlog via logman Windows utility
references:
    - https://twitter.com/0gtweet/status/1359039665232306183?s=21
    - https://ss64.com/nt/logman.html
tags:
    - attack.defense_evasion
    - attack.t1562.001
    - attack.t1070.001
author: Florian Roth 
date: 2021/02/11
modified: 2021/12/02
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools:
        CommandLine|contains:
           - 'logman '
    selection_action:
        CommandLine|contains:
            - 'stop '
            - 'delete '
    selection_service:
        CommandLine|contains: 
            - EventLog-System
    condition: all of selection*
falsepositives:
    - Legitimate deactivation by administrative staff
    - Installer tools that disable services, e.g. before log collection agent installation
level: high

```