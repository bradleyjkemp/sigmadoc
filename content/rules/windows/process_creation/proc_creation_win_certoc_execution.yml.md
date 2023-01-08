---
title: "Suspicious Load DLL via CertOC.exe"
aliases:
  - "/rule/242301bc-f92f-4476-8718-78004a6efd9f"
ruleid: 242301bc-f92f-4476-8718-78004a6efd9f

tags:
  - attack.defense_evasion
  - attack.t1218



status: experimental





date: Sat, 23 Oct 2021 14:10:40 -0500


---

Detects when a user installs certificates by using CertOC.exe to loads the target DLL file.

<!--more-->


## Known false-positives

* None



## References

* https://twitter.com/sblmsrsn/status/1445758411803480072?s=20


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_certoc_execution.yml))
```yaml
title: Suspicious Load DLL via CertOC.exe
id: 242301bc-f92f-4476-8718-78004a6efd9f
description: Detects when a user installs certificates by using CertOC.exe to loads the target DLL file.
status: experimental
author: Austin Songer @austinsonger
date: 2021/10/23
references:
- https://twitter.com/sblmsrsn/status/1445758411803480072?s=20
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certoc.exe'
        CommandLine|contains|all:
            - '-LoadDLL'
            - '.dll'
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
tags:
- attack.defense_evasion
- attack.t1218
level: medium
falsepositives:
- None


```
