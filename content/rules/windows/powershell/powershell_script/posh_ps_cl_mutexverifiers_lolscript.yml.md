---
title: "Execution via CL_Mutexverifiers.ps1"
aliases:
  - "/rule/39776c99-1c7b-4ba0-b5aa-641525eee1a4"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_cl_mutexverifiers_lolscript.yml))
```yaml
title: Execution via CL_Mutexverifiers.ps1
id: 39776c99-1c7b-4ba0-b5aa-641525eee1a4
description: Detects Execution via runAfterCancelProcess in CL_Mutexverifiers.ps1 module
status: experimental
author: oscd.community, Natalia Shornikova
date: 2020/10/14
modified: 2021/10/16
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSScripts/CL_mutexverifiers.yml
    - https://twitter.com/pabraeken/status/995111125447577600
tags:
    - attack.defense_evasion
    - attack.t1216
logsource:
    product: windows
    category: ps_script
    definition: Script block logging must be enabled
detection:
    selection:
        ScriptBlockText|contains|all:
          - 'CL_Mutexverifiers.ps1'
          - 'runAfterCancelProcess'
    condition: selection
falsepositives:
    - Unknown
level: high
```
