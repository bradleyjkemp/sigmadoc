---
title: "Run Whoami as SYSTEM"
aliases:
  - "/rule/80167ada-7a12-41ed-b8e9-aa47195c66a1"
ruleid: 80167ada-7a12-41ed-b8e9-aa47195c66a1

tags:
  - attack.privilege_escalation
  - attack.discovery
  - attack.t1033



status: experimental





date: Thu, 6 Feb 2020 23:41:05 +0100


---

Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.

<!--more-->


## Known false-positives

* Possible name overlap with NT AUHTORITY substring to cover all languages



## References

* https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_whoami_as_system.yml))
```yaml
title: Run Whoami as SYSTEM
id: 80167ada-7a12-41ed-b8e9-aa47195c66a1
status: experimental
description: Detects a whoami.exe executed by LOCAL SYSTEM. This may be a sign of a successful local privilege escalation.
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
author: Teymur Kheirkhabarov, Florian Roth
date: 2019/10/23
modified: 2022/01/28
tags:
    - attack.privilege_escalation
    - attack.discovery    
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User|contains: # covers many language settings
            - 'AUTHORI'
            - 'AUTORI'
        Image|endswith: '\whoami.exe'
    condition: selection
falsepositives:
    - Possible name overlap with NT AUHTORITY substring to cover all languages
level: high

```
