---
title: "Stop Windows Service"
aliases:
  - "/rule/eb87818d-db5d-49cc-a987-d5da331fbd90"
ruleid: eb87818d-db5d-49cc-a987-d5da331fbd90

tags:
  - attack.impact
  - attack.t1489



status: experimental





date: Wed, 23 Oct 2019 11:22:09 -0700


---

Detects a windows service to be stopped

<!--more-->


## Known false-positives

* Administrator shutting down the service due to upgrade or removal purposes




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_service_stop.yml))
```yaml
title: Stop Windows Service
id: eb87818d-db5d-49cc-a987-d5da331fbd90
description: Detects a windows service to be stopped
status: experimental
author: Jakob Weinzettl, oscd.community
date: 2019/10/23
modified: 2021/11/30
tags:
    - attack.impact
    - attack.t1489
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\sc.exe'
            - '\net.exe'
            - '\net1.exe'
        CommandLine|contains: 'stop'
    filter:
        CommandLine: 'sc  stop KSCWebConsoleMessageQueue' # kaspersky Security Center Web Console double space between sc and stop
        User|startswith: 
            - 'NT AUTHORITY\SYSTEM'
            - 'AUTORITE NT\Sys' # French language settings
    condition: selection and not filter
fields:
    - ComputerName
    - User
    - CommandLine
falsepositives:
    - Administrator shutting down the service due to upgrade or removal purposes
level: low

```
