---
title: "Indirect Command Execution"
aliases:
  - "/rule/fa47597e-90e9-41cd-ab72-c3b74cfb0d02"


tags:
  - attack.defense_evasion
  - attack.t1202



status: test





date: Mon, 28 Oct 2019 11:59:49 +0100


---

Detect indirect command execution via Program Compatibility Assistant (pcalua.exe or forfiles.exe).

<!--more-->


## Known false-positives

* Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts.
* Legitimate usage of scripts.



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.md
* https://eqllib.readthedocs.io/en/latest/analytics/884a7ccd-7305-4130-82d0-d4f90bc118b6.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_indirect_cmd.yml))
```yaml
title: Indirect Command Execution
id: fa47597e-90e9-41cd-ab72-c3b74cfb0d02
status: test
description: Detect indirect command execution via Program Compatibility Assistant (pcalua.exe or forfiles.exe).
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1202/T1202.md
  - https://eqllib.readthedocs.io/en/latest/analytics/884a7ccd-7305-4130-82d0-d4f90bc118b6.html
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\pcalua.exe'
      - '\forfiles.exe'
  condition: selection
fields:
  - ComputerName
  - User
  - ParentCommandLine
  - CommandLine
falsepositives:
  - Need to use extra processing with 'unique_count' / 'filter' to focus on outliers as opposed to commonly seen artifacts.
  - Legitimate usage of scripts.
level: low
tags:
  - attack.defense_evasion
  - attack.t1202

```
