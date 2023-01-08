---
title: "Interactive AT Job"
aliases:
  - "/rule/60fc936d-2eb0-4543-8a13-911c750a1dfc"
ruleid: 60fc936d-2eb0-4543-8a13-911c750a1dfc

tags:
  - attack.privilege_escalation
  - attack.t1053.002



status: test





date: Mon, 28 Oct 2019 11:59:49 +0100


---

Detect an interactive AT job, which may be used as a form of privilege escalation.

<!--more-->


## Known false-positives

* Unlikely (at.exe deprecated as of Windows 8)



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.002/T1053.002.md
* https://eqllib.readthedocs.io/en/latest/analytics/d8db43cf-ed52-4f5c-9fb3-c9a4b95a0b56.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_interactive_at.yml))
```yaml
title: Interactive AT Job
id: 60fc936d-2eb0-4543-8a13-911c750a1dfc
status: test
description: Detect an interactive AT job, which may be used as a form of privilege escalation.
author: E.M. Anhaus (originally from Atomic Blue Detections, Endgame), oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.002/T1053.002.md
  - https://eqllib.readthedocs.io/en/latest/analytics/d8db43cf-ed52-4f5c-9fb3-c9a4b95a0b56.html
date: 2019/10/24
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\at.exe'
    CommandLine|contains: 'interactive'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Unlikely (at.exe deprecated as of Windows 8)
level: high
tags:
  - attack.privilege_escalation
  - attack.t1053.002

```
