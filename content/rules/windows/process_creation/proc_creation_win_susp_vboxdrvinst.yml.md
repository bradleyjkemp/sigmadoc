---
title: "Suspicious VBoxDrvInst.exe Parameters"
aliases:
  - "/rule/b7b19cb6-9b32-4fc4-a108-73f19acfe262"


tags:
  - attack.defense_evasion
  - attack.t1112



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detect VBoxDrvInst.exe run with parameters allowing processing INF file. This allows to create values in the registry and install drivers. For example one could use this technique to obtain persistence via modifying one of Run or RunOnce registry keys

<!--more-->


## Known false-positives

* Legitimate use of VBoxDrvInst.exe utility by VirtualBox Guest Additions installation process



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OtherBinaries/VBoxDrvInst.yml
* https://twitter.com/pabraeken/status/993497996179492864


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_vboxdrvinst.yml))
```yaml
title: Suspicious VBoxDrvInst.exe Parameters
id: b7b19cb6-9b32-4fc4-a108-73f19acfe262
status: test
description: Detect VBoxDrvInst.exe run with parameters allowing processing INF file. This allows to create values in the registry and install drivers. For example one could use this technique to obtain persistence via modifying one of Run or RunOnce registry keys
author: Konstantin Grishchenko, oscd.community
references:
  - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/LOLUtilz/OtherBinaries/VBoxDrvInst.yml
  - https://twitter.com/pabraeken/status/993497996179492864
date: 2020/10/06
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\VBoxDrvInst.exe'
    CommandLine|contains|all:
      - 'driver'
      - 'executeinf'
  condition: selection
fields:
  - ComputerName
  - User
  - CommandLine
  - ParentCommandLine
falsepositives:
  - Legitimate use of VBoxDrvInst.exe utility by VirtualBox Guest Additions installation process
level: medium
tags:
  - attack.defense_evasion
  - attack.t1112

```
