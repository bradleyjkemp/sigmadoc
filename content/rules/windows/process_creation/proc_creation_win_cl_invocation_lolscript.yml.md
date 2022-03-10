---
title: "Execution via CL_Invocation.ps1"
aliases:
  - "/rule/a0459f02-ac51-4c09-b511-b8c9203fc429"


tags:
  - attack.defense_evasion
  - attack.t1216



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Execution via SyncInvoke in CL_Invocation.ps1 module

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSScripts/Cl_invocation.yml
* https://twitter.com/bohops/status/948061991012327424


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_cl_invocation_lolscript.yml))
```yaml
title: Execution via CL_Invocation.ps1
id: a0459f02-ac51-4c09-b511-b8c9203fc429
description: Detects Execution via SyncInvoke in CL_Invocation.ps1 module
status: experimental
author: oscd.community, Natalia Shornikova
date: 2020/10/14
modified: 2021/05/21
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSScripts/Cl_invocation.yml
    - https://twitter.com/bohops/status/948061991012327424
tags:
    - attack.defense_evasion
    - attack.t1216
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      CommandLine|contains|all: 
        - 'CL_Invocation.ps1'
        - 'SyncInvoke'
      # Example Commandline: "powershell Import-Module c:\Windows\diagnostics\system\Audio\CL_Invocation.ps1; SyncInvoke c:\Evil.exe"
    condition: selection
falsepositives: 
 - Unknown
level: high

```
