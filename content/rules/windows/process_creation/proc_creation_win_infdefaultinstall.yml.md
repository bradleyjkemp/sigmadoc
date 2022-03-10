---
title: "InfDefaultInstall.exe .inf Execution"
aliases:
  - "/rule/ce7cf472-6fcc-490a-9481-3786840b5d9b"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Wed, 7 Jul 2021 15:43:55 +0200


---

Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md
* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Infdefaultinstall.yml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_infdefaultinstall.yml))
```yaml
title: InfDefaultInstall.exe .inf Execution
id: ce7cf472-6fcc-490a-9481-3786840b5d9b
status: experimental
author: frack113
date: 2021/07/13
description: Executes SCT script using scrobj.dll from a command in entered into a specially prepared INF file.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218/T1218.md
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSBinaries/Infdefaultinstall.yml
tags:
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'InfDefaultInstall.exe '
            - '.inf'
    condition: selection 
fields:
    - ComputerName
    - User
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: medium

```