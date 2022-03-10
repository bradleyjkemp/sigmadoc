---
title: "Execution via CL_Invocation.ps1"
aliases:
  - "/rule/4cd29327-685a-460e-9dac-c3ab96e549dc"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_cl_invocation_lolscript.yml))
```yaml
title: Execution via CL_Invocation.ps1
id: 4cd29327-685a-460e-9dac-c3ab96e549dc
description: Detects Execution via SyncInvoke in CL_Invocation.ps1 module
status: experimental
author: oscd.community, Natalia Shornikova
date: 2020/10/14
modified: 2021/10/16
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OSScripts/Cl_invocation.yml
    - https://twitter.com/bohops/status/948061991012327424
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
          - 'CL_Invocation.ps1'
          - 'SyncInvoke'
    condition: selection
falsepositives:
    - Unknown
level: high

```
