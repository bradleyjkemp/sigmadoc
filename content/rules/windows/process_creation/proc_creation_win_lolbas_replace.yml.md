---
title: "Suspicious Replace.exe Execution"
aliases:
  - "/rule/9292293b-8496-4715-9db6-37028dcda4b3"


tags:
  - attack.command_and_control
  - attack.t1105



status: experimental





date: Sun, 6 Mar 2022 12:10:51 +0100


---

Replace.exe is used to replace file with another file

<!--more-->


## Known false-positives

* unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/Replace/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbas_replace.yml))
```yaml
title: Suspicious Replace.exe Execution
id: 9292293b-8496-4715-9db6-37028dcda4b3
status: experimental
description: Replace.exe is used to replace file with another file
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Replace/
author: frack113
date: 2022/03/06
logsource:
    category: process_creation
    product: windows
detection:
    lolbas:
        CommandLine|contains|all: 
            - 'replace '
            - '/A'
    condition: lolbas 
falsepositives:
    - unknown
level: medium
tags:
    - attack.command_and_control
    - attack.t1105
```
