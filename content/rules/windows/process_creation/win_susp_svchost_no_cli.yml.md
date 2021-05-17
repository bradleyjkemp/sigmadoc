---
title: "Suspect Svchost Activity"
aliases:
  - "/rule/16c37b52-b141-42a5-a3ea-bbe098444397"

tags:
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1055



status: experimental



level: critical



date: Sat, 28 Dec 2019 10:28:08 -0500


---

It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.

<!--more-->


## Known false-positives

* rpcnet.exe / rpcnetp.exe which is a lojack style software. https://www.blackhat.com/docs/us-14/materials/us-14-Kamlyuk-Kamluk-Computrace-Backdoor-Revisited.pdf



## References

* https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2


## Raw rule
```yaml
title: Suspect Svchost Activity
id: 16c37b52-b141-42a5-a3ea-bbe098444397
status: experimental
description: It is extremely abnormal for svchost.exe to spawn without any CLI arguments and is normally observed when a malicious process spawns the process and injects code into the process memory space.
references:
    - https://securitybytes.io/blue-team-fundamentals-part-two-windows-processes-759fe15965e2
author: David Burkett
date: 2019/12/28
modified: 2020/08/28
tags:
    - attack.defense_evasion
    - attack.privilege_escalation    
    - attack.t1055
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|endswith: 'svchost.exe' 
    selection2:
        Image|endswith: '\svchost.exe'
    filter:
        ParentImage|endswith:
            - '\rpcnet.exe'
            - '\rpcnetp.exe'
    condition: (selection1 and selection2) and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - rpcnet.exe / rpcnetp.exe which is a lojack style software. https://www.blackhat.com/docs/us-14/materials/us-14-Kamlyuk-Kamluk-Computrace-Backdoor-Revisited.pdf
level: critical

```
