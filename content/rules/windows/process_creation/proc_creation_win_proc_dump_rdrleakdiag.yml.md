---
title: "RdrLeakDiag Process Dump"
aliases:
  - "/rule/6355a919-2e97-4285-a673-74645566340d"
ruleid: 6355a919-2e97-4285-a673-74645566340d

tags:
  - attack.defense_evasion
  - attack.t1036
  - attack.t1003.001



status: experimental





date: Tue, 4 Jan 2022 08:51:06 +0100


---

Detects uses of the rdrleakdiag.exe LOLOBIN utility to dump process memory

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.crowdstrike.com/blog/overwatch-exposes-aquatic-panda-in-possession-of-log-4-shell-exploit-tools/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_proc_dump_rdrleakdiag.yml))
```yaml
title: RdrLeakDiag Process Dump
id: 6355a919-2e97-4285-a673-74645566340d
description: Detects uses of the rdrleakdiag.exe LOLOBIN utility to dump process memory 
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
        Image|endswith: '\rdrleakdiag.exe'
        CommandLine|contains|all:
            - '/fullmemdmp'
    selection2:
        CommandLine|contains|all:
            - '/fullmemdmp'
            - ' /o '
            - ' /p '
    condition: selection1 or selection2
falsepositives:
    - Unknown
level: high

```
