---
title: "Winnti Pipemon Characteristics"
aliases:
  - "/rule/73d70463-75c9-4258-92c6-17500fe972f2"
ruleid: 73d70463-75c9-4258-92c6-17500fe972f2

tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.g0044



status: stable





date: Thu, 30 Jul 2020 18:55:47 +0200


---

Detects specific process characteristics of Winnti Pipemon malware reported by ESET

<!--more-->


## Known false-positives

* Legitimate setups that use similar flags



## References

* https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_winnti_pipemon.yml))
```yaml
title: Winnti Pipemon Characteristics
id: 73d70463-75c9-4258-92c6-17500fe972f2
status: stable
description: Detects specific process characteristics of Winnti Pipemon malware reported by ESET
author: Florian Roth, oscd.community
references:
  - https://www.welivesecurity.com/2020/05/21/no-game-over-winnti-group/
date: 2020/07/30
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    CommandLine|contains:
      - 'setup0.exe -p'
  selection2:
    CommandLine|contains|all:
      - 'setup.exe'
    CommandLine|endswith:
      - '-x:0'
      - '-x:1'
      - '-x:2'
  condition: 1 of selection*
falsepositives:
  - Legitimate setups that use similar flags
level: critical
tags:
  - attack.defense_evasion
  - attack.t1574.002
  - attack.g0044

```
