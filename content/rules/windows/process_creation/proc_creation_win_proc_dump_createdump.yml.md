---
title: "CreateDump Process Dump"
aliases:
  - "/rule/515c8be5-e5df-4c5e-8f6d-a4a2f05e4b48"


tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1003.001



status: experimental





date: Tue, 4 Jan 2022 08:51:06 +0100


---

Detects uses of the createdump.exe LOLOBIN utility to dump process memory

<!--more-->


## Known false-positives

* Command lines that use the same flags



## References

* https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_proc_dump_createdump.yml))
```yaml
title: CreateDump Process Dump
id: 515c8be5-e5df-4c5e-8f6d-a4a2f05e4b48
description: Detects uses of the createdump.exe LOLOBIN utility to dump process memory 
status: experimental
references:
    - https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/
author: Florian Roth
date: 2022/01/04
tags:
    - attack.defense_evasion
    - attack.t1036
    - attack.t1003.001
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        Image|endswith: '\createdump.exe'
        CommandLine|contains|all:
            - ' -u '
            - ' -f '
    selection2:
        CommandLine|contains|all:
            - ' -u -f '
            - '.dmp '
    condition: selection1 or selection2
falsepositives:
    - Command lines that use the same flags
level: high

```
