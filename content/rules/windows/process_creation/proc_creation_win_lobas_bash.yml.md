---
title: "Suspicious Subsystem for Linux Bash Execution"
aliases:
  - "/rule/5edc2273-c26f-406c-83f3-f4d948e740dd"


tags:
  - attack.defense_evasion
  - attack.t1202



status: experimental





date: Wed, 24 Nov 2021 19:17:00 +0100


---

Performs execution of specified file, can be used as a defensive evasion.

<!--more-->


## Known false-positives

* unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/Bash/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lobas_bash.yml))
```yaml
title: Suspicious Subsystem for Linux Bash Execution
id: 5edc2273-c26f-406c-83f3-f4d948e740dd
status: experimental
description: Performs execution of specified file, can be used as a defensive evasion. 
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Bash/
tags:
    - attack.defense_evasion
    - attack.t1202
author: frack113
date: 2021/11/24
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - bash.exe
            - '-c '
    condition: selection
falsepositives:
    - unknown
level: medium

```
