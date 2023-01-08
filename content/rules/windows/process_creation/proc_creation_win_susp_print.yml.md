---
title: "Abusing Print Executable"
aliases:
  - "/rule/bafac3d6-7de9-4dd9-8874-4a1194b493ed"
ruleid: bafac3d6-7de9-4dd9-8874-4a1194b493ed

tags:
  - attack.defense_evasion
  - attack.t1218



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Attackers can use print.exe for remote file copy

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Print.yml
* https://twitter.com/Oddvarmoe/status/985518877076541440


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_print.yml))
```yaml
title: Abusing Print Executable
id: bafac3d6-7de9-4dd9-8874-4a1194b493ed
status: test
description: Attackers can use print.exe for remote file copy
author: 'Furkan CALISKAN, @caliskanfurkan_, @oscd_initiative'
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Print.yml
  - https://twitter.com/Oddvarmoe/status/985518877076541440
date: 2020/10/05
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    Image|endswith:
      - \print.exe
    CommandLine|startswith:
      - print
  selection2:
    CommandLine|contains:
      - /D
  exeCondition:
    CommandLine|contains:
      - .exe
  cmdExclude:
    CommandLine|contains:
      - print.exe
  condition: selection1 and selection2 and exeCondition and not cmdExclude
falsepositives:
  - Unknown
level: medium
tags:
  - attack.defense_evasion
  - attack.t1218

```
