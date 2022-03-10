---
title: "Raccine Uninstall"
aliases:
  - "/rule/a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool.

<!--more-->


## Known false-positives

* Legitimate deinstallation by administrative staff



## References

* https://github.com/Neo23x0/Raccine


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_disable_raccine.yml))
```yaml
title: Raccine Uninstall
id: a31eeaed-3fd5-478e-a8ba-e62c6b3f9ecc
status: experimental
description: Detects commands that indicate a Raccine removal from an end system. Raccine is a free ransomware protection tool. 
references:
    - https://github.com/Neo23x0/Raccine
tags:
    - attack.defense_evasion
    - attack.t1562.001
author: Florian Roth 
date: 2021/01/21
modified: 2021/07/14
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all:
            - 'taskkill '
            - 'RaccineSettings.exe'
    selection2:
        CommandLine|contains|all:
            - 'reg.exe'
            - 'delete'
            - 'Raccine Tray'
    selection3:
        CommandLine|contains|all:
            - 'schtasks'
            - '/DELETE'
            - 'Raccine Rules Updater'
    condition: 1 of selection*
falsepositives:
    - Legitimate deinstallation by administrative staff
level: high

```
