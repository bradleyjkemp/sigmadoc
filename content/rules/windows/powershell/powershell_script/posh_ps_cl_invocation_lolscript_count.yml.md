---
title: "Execution via CL_Invocation.ps1 (2 Lines)"
aliases:
  - "/rule/f588e69b-0750-46bb-8f87-0e9320d57536"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_script/posh_ps_cl_invocation_lolscript_count.yml))
```yaml
title: Execution via CL_Invocation.ps1 (2 Lines)
id: f588e69b-0750-46bb-8f87-0e9320d57536
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
        ScriptBlockText|contains:
          - 'CL_Invocation.ps1'
          - 'SyncInvoke'
    condition: selection | count(ScriptBlockText) by Computer > 2
      # PS > Import-Module c:\Windows\diagnostics\system\Audio\CL_Invocation.ps1
      # PS > SyncInvoke c:\Evil.exe
falsepositives:
    - Unknown
level: high

```
