---
title: "Default PowerSploit and Empire Schtasks Persistence"
aliases:
  - "/rule/56c217c3-2de2-479b-990f-5c109ba8458f"

tags:
  - attack.execution
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1053
  - attack.t1086
  - attack.s0111
  - attack.g0022
  - attack.g0060
  - car.2013-08-001
  - attack.t1053.005
  - attack.t1059.001



status: experimental



level: high



date: Sat, 23 Jun 2018 15:45:58 +0200


---

Detects the creation of a schtask via PowerSploit or Empire Default Configuration.

<!--more-->


## Known false-positives

* False positives are possible, depends on organisation and processes



## References

* https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
* https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py
* https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py


## Raw rule
```yaml
title: Default PowerSploit and Empire Schtasks Persistence
id: 56c217c3-2de2-479b-990f-5c109ba8458f
status: experimental
description: Detects the creation of a schtask via PowerSploit or Empire Default Configuration.
references:
    - https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
    - https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/userland/schtasks.py
    - https://github.com/EmpireProject/Empire/blob/master/lib/modules/powershell/persistence/elevated/schtasks.py
author: Markus Neis, @Karneades
date: 2018/03/06
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        ParentImage:
            - '*\powershell.exe'
        CommandLine:
            - '*schtasks*/Create*/SC *ONLOGON*/TN *Updater*/TR *powershell*'
            - '*schtasks*/Create*/SC *DAILY*/TN *Updater*/TR *powershell*'
            - '*schtasks*/Create*/SC *ONIDLE*/TN *Updater*/TR *powershell*'
            - '*schtasks*/Create*/SC *Updater*/TN *Updater*/TR *powershell*'
    condition: selection
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053 # an old one
    - attack.t1086 # an old one
    - attack.s0111
    - attack.g0022
    - attack.g0060
    - car.2013-08-001
    - attack.t1053.005
    - attack.t1059.001
falsepositives:
    - False positives are possible, depends on organisation and processes
level: high

```
