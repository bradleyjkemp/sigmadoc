---
title: "Regedit as Trusted Installer"
aliases:
  - "/rule/883835a7-df45-43e4-bf1d-4268768afda4"
ruleid: 883835a7-df45-43e4-bf1d-4268768afda4

tags:
  - attack.privilege_escalation
  - attack.t1548



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe

<!--more-->


## Known false-positives

* Unlikely



## References

* https://twitter.com/1kwpeter/status/1397816101455765504


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_regedit_trustedinstaller.yml))
```yaml
title: Regedit as Trusted Installer
id: 883835a7-df45-43e4-bf1d-4268768afda4
description: Detects a regedit started with TrustedInstaller privileges or by ProcessHacker.exe
status: experimental
references:
    - https://twitter.com/1kwpeter/status/1397816101455765504
author: Florian Roth
date: 2021/05/27
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regedit.exe'
        ParentImage|endswith: 
            - '\TrustedInstaller.exe'
            - '\ProcessHacker.exe'
    condition: selection
falsepositives:
    - Unlikely
level: high
tags:
    - attack.privilege_escalation
    - attack.t1548 
```
