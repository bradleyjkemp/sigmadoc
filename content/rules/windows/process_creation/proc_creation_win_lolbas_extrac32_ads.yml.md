---
title: "Suspicious Extrac32 Alternate Data Stream Execution"
aliases:
  - "/rule/4b13db67-0c45-40f1-aba8-66a1a7198a1e"


tags:
  - attack.defense_evasion
  - attack.t1564.004



status: experimental





date: Sat, 27 Nov 2021 10:15:24 +0100


---

Extract data from cab file and hide it in an alternate data stream

<!--more-->


## Known false-positives

* unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/Extrac32/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbas_extrac32_ads.yml))
```yaml
title: Suspicious Extrac32 Alternate Data Stream Execution 
id: 4b13db67-0c45-40f1-aba8-66a1a7198a1e
status: experimental
description: Extract data from cab file and hide it in an alternate data stream
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
        CommandLine|re: ':[^\\\\]'
    condition: lolbas 
falsepositives:
    - unknown
level: medium

```
