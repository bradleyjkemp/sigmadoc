---
title: "Suspicious Diantz Download and Compress Into a CAB File"
aliases:
  - "/rule/185d7418-f250-42d0-b72e-0c8b70661e93"


tags:
  - attack.command_and_control
  - attack.t1105



status: experimental





date: Fri, 26 Nov 2021 18:50:19 +0100


---

Download and compress a remote file and store it in a cab file on local machine.

<!--more-->


## Known false-positives

* unknown



## References

* https://lolbas-project.github.io/lolbas/Binaries/Diantz/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_lolbas_diantz_remote_cab.yml))
```yaml
title: Suspicious Diantz Download and Compress Into a CAB File
id: 185d7418-f250-42d0-b72e-0c8b70661e93
status: experimental
description: Download and compress a remote file and store it in a cab file on local machine. 
references:
    - https://lolbas-project.github.io/lolbas/Binaries/Diantz/
tags:
    - attack.command_and_control
    - attack.t1105
author: frack113
date: 2021/11/26
logsource:
    category: process_creation
    product: windows
detection:
    lolbas:
        CommandLine|contains|all:
            - diantz.exe
            - ' \\' 
            - '.cab'
    condition: lolbas 
falsepositives:
    - unknown
level: medium

```
