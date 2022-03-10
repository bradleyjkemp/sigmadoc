---
title: "Execution via CL_Mutexverifiers.ps1"
aliases:
  - "/rule/99465c8f-f102-4157-b11c-b0cddd53b79a"


tags:
  - attack.defense_evasion
  - attack.t1216



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Execution via runAfterCancelProcess in CL_Mutexverifiers.ps1 module

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSScripts/CL_mutexverifiers.yml
* https://twitter.com/pabraeken/status/995111125447577600


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_cl_mutexverifiers_lolscript.yml))
```yaml
title: Execution via CL_Mutexverifiers.ps1
id: 99465c8f-f102-4157-b11c-b0cddd53b79a
description: Detects Execution via runAfterCancelProcess in CL_Mutexverifiers.ps1 module
status: experimental
author: oscd.community, Natalia Shornikova
date: 2020/10/14
modified: 2021/05/21
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSScripts/CL_mutexverifiers.yml
    - https://twitter.com/pabraeken/status/995111125447577600
tags:
    - attack.defense_evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      CommandLine|contains|all: 
        - 'CL_Mutexverifiers.ps1'
        - 'runAfterCancelProcess'
      # Example Commandline: "powershell Import-Module c:\Windows\diagnostics\system\Audio\CL_Mutexverifiers.ps1; runAfterCancelProcess c:\Evil.exe"
    condition: selection
falsepositives:
 - Unknown
level: high

```
