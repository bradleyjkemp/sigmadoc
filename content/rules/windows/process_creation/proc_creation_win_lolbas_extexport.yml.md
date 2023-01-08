---
title: "Suspicious Extexport Execution"
aliases:
  - "/rule/fb0b815b-f5f6-4f50-970f-ffe21f253f7a"
ruleid: fb0b815b-f5f6-4f50-970f-ffe21f253f7a

tags:
  - attack.defense_evasion
  - attack.t1218



status: experimental





date: Fri, 26 Nov 2021 18:50:19 +0100


---

Extexport.exe loads dll and is execute from other folder the original path

<!--more-->


## Known false-positives

* unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/Extexport/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbas_extexport.yml))
```yaml
title: Suspicious Extexport Execution
id: fb0b815b-f5f6-4f50-970f-ffe21f253f7a
status: experimental
description: Extexport.exe loads dll and is execute from other folder the original path
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Extexport/
tags:
    - attack.defense_evasion
    - attack.t1218
author: frack113
date: 2021/11/26
logsource:
    category: process_creation
    product: windows
detection:
    lolbas:
        CommandLine|contains: Extexport.exe
    condition: lolbas 
falsepositives:
    - unknown
level: medium

```
