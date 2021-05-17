---
title: "Run Whoami as SYSTEM"
aliases:
  - "/rule/80167ada-7a12-41ed-b8e9-aa47195c66a1"

tags:
  - attack.privilege_escalation
  - attack.discovery
  - attack.t1033



status: experimental



level: high



date: Thu, 6 Feb 2020 23:41:05 +0100


---

Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.

<!--more-->


## Known false-positives

* Unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment


## Raw rule
```yaml
title: Run Whoami as SYSTEM
id: 80167ada-7a12-41ed-b8e9-aa47195c66a1
status: experimental
description: Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
author: Teymur Kheirkhabarov
date: 2019/10/23
modified: 2019/11/11
tags:
    - attack.privilege_escalation
    - attack.discovery    
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User: 'NT AUTHORITY\SYSTEM'
        Image|endswith: '\whoami.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
