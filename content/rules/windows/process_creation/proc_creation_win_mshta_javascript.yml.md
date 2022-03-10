---
title: "Mshta JavaScript Execution"
aliases:
  - "/rule/67f113fa-e23d-4271-befa-30113b3e08b1"


tags:
  - attack.defense_evasion
  - attack.t1218.005



status: test





date: Mon, 28 Oct 2019 11:59:49 +0100


---

Identifies suspicious mshta.exe commands.

<!--more-->


## Known false-positives

* unknown



## References

* https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_mshta_javascript.yml))
```yaml
title: Mshta JavaScript Execution
id: 67f113fa-e23d-4271-befa-30113b3e08b1
status: test
description: Identifies suspicious mshta.exe commands.
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
references:
  - https://eqllib.readthedocs.io/en/latest/analytics/6bc283c4-21f2-4aed-a05c-a9a3ffa95dd4.html
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\mshta.exe'
    CommandLine|contains: 'javascript'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - unknown
level: high
tags:
  - attack.defense_evasion
  - attack.t1218.005

```
