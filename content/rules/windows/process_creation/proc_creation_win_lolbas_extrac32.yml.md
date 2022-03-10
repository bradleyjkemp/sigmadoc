---
title: "Suspicious Extrac32 Execution"
aliases:
  - "/rule/aa8e035d-7be4-48d3-a944-102aec04400d"


tags:
  - attack.defense_evasion
  - attack.t1564.004



status: experimental





date: Fri, 26 Nov 2021 18:50:19 +0100


---

Download or Copy file with Extrac32

<!--more-->


## Known false-positives

* unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/Extrac32/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbas_extrac32.yml))
```yaml
title: Suspicious Extrac32 Execution
id: aa8e035d-7be4-48d3-a944-102aec04400d
status: experimental
description: Download or Copy file with Extrac32
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Extrac32/
tags:
    - attack.defense_evasion
    - attack.t1564.004 
author: frack113
date: 2021/11/26
logsource:
    category: process_creation
    product: windows
detection:
    lolbas:
        CommandLine|contains|all:
            - extrac32.exe
            - .cab
    options:
        CommandLine|contains:
            - /C
            - /Y
            - ' \\'
    condition: lolbas and options
falsepositives:
    - unknown
level: medium

```
