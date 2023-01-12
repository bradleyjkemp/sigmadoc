---
title: "Suspicious Bitsadmin Job via PowerShell"
aliases:
  - "/rule/f67dbfce-93bc-440d-86ad-a95ae8858c90"
ruleid: f67dbfce-93bc-440d-86ad-a95ae8858c90

tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1197



status: test





date: Mon, 28 Oct 2019 11:59:49 +0100


---

Detect download by BITS jobs via PowerShell

<!--more-->


## Known false-positives

* Unknown



## References

* https://eqllib.readthedocs.io/en/latest/analytics/ec5180c9-721a-460f-bddc-27539a284273.html
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_powershell_bitsjob.yml))
```yaml
title: Suspicious Bitsadmin Job via PowerShell
id: f67dbfce-93bc-440d-86ad-a95ae8858c90
status: test
description: Detect download by BITS jobs via PowerShell
author: Endgame, JHasenbusch (ported to sigma for oscd.community)
references:
  - https://eqllib.readthedocs.io/en/latest/analytics/ec5180c9-721a-460f-bddc-27539a284273.html
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md
date: 2018/10/30
modified: 2021/12/03
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: 'Start-BitsTransfer'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
falsepositives:
  - Unknown
level: high
tags:
  - attack.defense_evasion
  - attack.persistence
  - attack.t1197

```