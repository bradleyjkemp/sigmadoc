---
title: "Set Windows System File with Attrib"
aliases:
  - "/rule/bb19e94c-59ae-4c15-8c12-c563d23fe52b"
ruleid: bb19e94c-59ae-4c15-8c12-c563d23fe52b

tags:
  - attack.defense_evasion
  - attack.t1564.001



status: experimental





date: Fri, 4 Feb 2022 10:49:50 +0100


---

Marks a file as a system file using the attrib.exe utility

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md#atomic-test-3---create-windows-system-file-with-attrib
* https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/attrib


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_attrib_system.yml))
```yaml
title: Set Windows System File with Attrib
id: bb19e94c-59ae-4c15-8c12-c563d23fe52b
status: experimental
description: Marks a file as a system file using the attrib.exe utility
author: frack113
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1564.001/T1564.001.md#atomic-test-3---create-windows-system-file-with-attrib
    - https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/attrib
date: 2022/02/04
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: \attrib.exe
        CommandLine|contains: ' +s '
    condition: selection
falsepositives:
    - Unknown
level: low
tags:
    - attack.defense_evasion
    - attack.t1564.001
```
