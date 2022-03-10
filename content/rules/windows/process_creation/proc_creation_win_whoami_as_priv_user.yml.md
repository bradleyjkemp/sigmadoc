---
title: "Run Whoami as Privileged User"
aliases:
  - "/rule/79ce34ca-af29-4d0e-b832-fc1b377020db"


tags:
  - attack.privilege_escalation
  - attack.discovery
  - attack.t1033



status: experimental





date: Fri, 28 Jan 2022 11:30:30 +0100


---

Detects a whoami.exe executed by privileged accounts that are often misused by threat actors

<!--more-->


## Known false-positives

* Unknown



## References

* https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
* https://nsudo.m2team.org/en-us/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_whoami_as_priv_user.yml))
```yaml
title: Run Whoami as Privileged User
id: 79ce34ca-af29-4d0e-b832-fc1b377020db
status: experimental
description: Detects a whoami.exe executed by privileged accounts that are often misused by threat actors
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://nsudo.m2team.org/en-us/
author: Florian Roth
date: 2022/01/28
tags:
    - attack.privilege_escalation
    - attack.discovery
    - attack.t1033
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        User|contains: 'TrustedInstaller'
        Image|endswith: '\whoami.exe'
    condition: selection
falsepositives:
    - Unknown
level: high

```
