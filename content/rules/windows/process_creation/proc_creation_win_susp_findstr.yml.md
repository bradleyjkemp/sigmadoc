---
title: "Abusing Findstr for Defense Evasion"
aliases:
  - "/rule/bf6c39fc-e203-45b9-9538-05397c1b4f3f"


tags:
  - attack.defense_evasion
  - attack.t1218



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Attackers can use findstr to hide their artifacts or search specific strings and evade defense mechanism

<!--more-->


## Known false-positives

* Administrative findstr usage



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Findstr.yml
* https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/
* https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_findstr.yml))
```yaml
title: Abusing Findstr for Defense Evasion
id: bf6c39fc-e203-45b9-9538-05397c1b4f3f
status: test
description: Attackers can use findstr to hide their artifacts or search specific strings and evade defense mechanism
author: 'Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative'
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Findstr.yml
  - https://oddvar.moe/2018/04/11/putting-data-in-alternate-data-streams-and-how-to-execute-it-part-2/
  - https://gist.github.com/api0cradle/cdd2d0d0ec9abb686f0e89306e277b8f
date: 2020/10/05
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selectionFindstr:
    CommandLine|contains:
      - findstr
  selection_V_L:
    CommandLine|contains|all:
      - /V
      - /L
  selection_S_I:
    CommandLine|contains|all:
      - /S
      - /I
  condition: selectionFindstr and (selection_V_L or selection_S_I)
falsepositives:
  - Administrative findstr usage
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218

```
