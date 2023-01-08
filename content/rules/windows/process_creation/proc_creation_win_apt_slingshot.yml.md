---
title: "Defrag Deactivation"
aliases:
  - "/rule/958d81aa-8566-4cea-a565-59ccd4df27b0"
ruleid: 958d81aa-8566-4cea-a565-59ccd4df27b0

tags:
  - attack.persistence
  - attack.t1053.005
  - attack.s0111



status: experimental





date: Sat, 10 Mar 2018 15:49:50 +0100


---

Detects the deactivation and disabling of the Scheduled defragmentation task as seen by Slingshot APT group

<!--more-->


## Known false-positives

* Unknown



## References

* https://securelist.com/apt-slingshot/84312/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_slingshot.yml))
```yaml
title: Defrag Deactivation
id: 958d81aa-8566-4cea-a565-59ccd4df27b0
description: Detects the deactivation and disabling of the Scheduled defragmentation task as seen by Slingshot APT group
status: experimental
author: Florian Roth, Bartlomiej Czyz (@bczyz1)
date: 2019/03/04
modified: 2021/09/19
references:
    - https://securelist.com/apt-slingshot/84312/
tags:
    - attack.persistence
    - attack.t1053.005
    - attack.s0111
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\schtasks.exe'
        CommandLine|contains:
            - '/delete'
            - '/change'
        CommandLine|contains|all:
            - '/TN'
            - '\Microsoft\Windows\Defrag\ScheduledDefrag'
    condition: selection
falsepositives:
    - Unknown
level: medium
```
