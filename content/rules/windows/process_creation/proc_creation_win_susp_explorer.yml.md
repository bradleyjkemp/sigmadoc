---
title: "Proxy Execution Via Explorer.exe"
aliases:
  - "/rule/9eb271b9-24ae-4cd4-9465-19cfc1047f3e"


tags:
  - attack.defense_evasion
  - attack.t1218



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Attackers can use explorer.exe for evading defense mechanisms

<!--more-->


## Known false-positives

* Legitimate explorer.exe run from cmd.exe



## References

* https://twitter.com/CyberRaiju/status/1273597319322058752


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_explorer.yml))
```yaml
title: Proxy Execution Via Explorer.exe
id: 9eb271b9-24ae-4cd4-9465-19cfc1047f3e
status: test
description: Attackers can use explorer.exe for evading defense mechanisms
author: 'Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative'
references:
  - https://twitter.com/CyberRaiju/status/1273597319322058752
date: 2020/10/05
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - \explorer.exe
    ParentImage|endswith:
      - \cmd.exe
    CommandLine|contains:
      - explorer.exe
  condition: selection
falsepositives:
  - Legitimate explorer.exe run from cmd.exe
level: low
tags:
  - attack.defense_evasion
  - attack.t1218

```
