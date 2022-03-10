---
title: "Suspicious Diantz Alternate Data Stream Execution"
aliases:
  - "/rule/6b369ced-4b1d-48f1-b427-fdc0de0790bd"


tags:
  - attack.defense_evasion
  - attack.t1564.004



status: experimental





date: Fri, 26 Nov 2021 18:50:19 +0100


---

Compress taget file into a cab file stored in the Alternate Data Stream (ADS) of the target file.

<!--more-->


## Known false-positives

* Very Possible



## References

* https://lolbas-project.github.io/lolbas/Binaries/Diantz/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbas_diantz_ads.yml))
```yaml
title: Suspicious Diantz Alternate Data Stream Execution 
id: 6b369ced-4b1d-48f1-b427-fdc0de0790bd
status: experimental
description: Compress taget file into a cab file stored in the Alternate Data Stream (ADS) of the target file.
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
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
            - diantz.exe
            - .cab
        CommandLine|re: ':[^\\\\]'
    condition: lolbas 
falsepositives:
    - Very Possible
level: medium

```
