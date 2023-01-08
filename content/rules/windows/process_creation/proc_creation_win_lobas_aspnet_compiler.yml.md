---
title: "Suspicious aspnet_compiler.exe Execution"
aliases:
  - "/rule/a01b8329-5953-4f73-ae2d-aa01e1f35f00"
ruleid: a01b8329-5953-4f73-ae2d-aa01e1f35f00

tags:
  - attack.defense_evasion
  - attack.t1127



status: experimental





date: Wed, 24 Nov 2021 19:17:00 +0100


---

Execute C# code with the Build Provider and proper folder structure in place.

<!--more-->


## Known false-positives

* unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lobas_aspnet_compiler.yml))
```yaml
title: Suspicious aspnet_compiler.exe Execution
id: a01b8329-5953-4f73-ae2d-aa01e1f35f00
status: experimental
description: Execute C# code with the Build Provider and proper folder structure in place.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Aspnet_Compiler/
tags:
    - attack.defense_evasion
    - attack.t1127
author: frack113
date: 2021/11/24
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|contains|all:
            - C:\Windows\Microsoft.NET\Framework
            - aspnet_compiler.exe
    condition: selection
falsepositives:
    - unknown
level: medium

```
