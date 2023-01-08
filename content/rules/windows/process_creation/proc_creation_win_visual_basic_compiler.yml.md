---
title: "Visual Basic Command Line Compiler Usage"
aliases:
  - "/rule/7b10f171-7f04-47c7-9fa2-5be43c76e535"
ruleid: 7b10f171-7f04-47c7-9fa2-5be43c76e535

tags:
  - attack.defense_evasion
  - attack.t1027.004



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects successful code compilation via Visual Basic Command Line Compiler that utilizes Windows Resource to Object Converter.

<!--more-->


## Known false-positives

* Utilization of this tool should not be seen in enterprise environment



## References

* https://lolbas-project.github.io/lolbas/Binaries/Vbc/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_visual_basic_compiler.yml))
```yaml
title: Visual Basic Command Line Compiler Usage
id: 7b10f171-7f04-47c7-9fa2-5be43c76e535
status: test
description: Detects successful code compilation via Visual Basic Command Line Compiler that utilizes Windows Resource to Object Converter.
author: 'Ensar Şamil, @sblmsrsn, @oscd_initiative'
references:
  - https://lolbas-project.github.io/lolbas/Binaries/Vbc/
date: 2020/10/07
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: '\vbc.exe'
    Image|endswith: '\cvtres.exe'
  condition: selection
falsepositives:
  - Utilization of this tool should not be seen in enterprise environment
level: high
tags:
  - attack.defense_evasion
  - attack.t1027.004

```
