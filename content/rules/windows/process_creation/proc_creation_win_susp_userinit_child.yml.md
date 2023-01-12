---
title: "Suspicious Userinit Child Process"
aliases:
  - "/rule/b655a06a-31c0-477a-95c2-3726b83d649d"
ruleid: b655a06a-31c0-477a-95c2-3726b83d649d

tags:
  - attack.defense_evasion
  - attack.t1055



status: experimental





date: Sun, 23 Jun 2019 13:27:06 +0200


---

Detects a suspicious child process of userinit

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://twitter.com/SBousseaden/status/1139811587760562176


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_userinit_child.yml))
```yaml
title: Suspicious Userinit Child Process
id: b655a06a-31c0-477a-95c2-3726b83d649d
status: experimental
description: Detects a suspicious child process of userinit
references:
    - https://twitter.com/SBousseaden/status/1139811587760562176
author: Florian Roth (rule), Samir Bousseaden (idea)
date: 2019/06/17
modified: 2021/06/27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\userinit.exe'
    filter1:
        CommandLine|contains: '\netlogon\'
    filter2:
        Image|endswith: '\explorer.exe'
    condition: selection and not filter1 and not filter2
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative scripts
level: medium
tags:
    - attack.defense_evasion
    - attack.t1055
```