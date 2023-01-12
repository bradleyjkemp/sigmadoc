---
title: "PowerShell Script Run in AppData"
aliases:
  - "/rule/ac175779-025a-4f12-98b0-acdaeb77ea85"
ruleid: ac175779-025a-4f12-98b0-acdaeb77ea85

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Wed, 16 Jan 2019 23:36:31 +0100


---

Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://twitter.com/JohnLaTwC/status/1082851155481288706
* https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_ps_appdata.yml))
```yaml
title: PowerShell Script Run in AppData
id: ac175779-025a-4f12-98b0-acdaeb77ea85
status: experimental
description: Detects a suspicious command line execution that invokes PowerShell with reference to an AppData folder
references:
    - https://twitter.com/JohnLaTwC/status/1082851155481288706
    - https://app.any.run/tasks/f87f1c4e-47e2-4c46-9cf4-31454c06ce03
tags:
    - attack.execution
    - attack.t1059.001
author: Florian Roth, Jonhnathan Ribeiro, oscd.community
date: 2019/01/09
modified: 2021/11/28
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'powershell.exe'
            - '\powershell'
    selection2:
        CommandLine|contains|all:
            - '/c '
            - '\AppData\'
        CommandLine|contains:
            - 'Local\'
            - 'Roaming\'
    condition: selection1 and selection2
falsepositives:
    - Administrative scripts
level: medium

```