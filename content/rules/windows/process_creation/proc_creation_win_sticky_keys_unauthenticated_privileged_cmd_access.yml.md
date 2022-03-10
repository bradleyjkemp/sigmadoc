---
title: "Using Sticky-keys To Obtain Unauthenticated, Privileged Console Access"
aliases:
  - "/rule/1070db9a-3e5d-412e-8e7b-7183b616e1b3"


tags:
  - attack.t1546.008
  - attack.privilege_escalation



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

By replacing the sticky keys executable with the local admins CMD executable, an attacker is able to access a privileged windows console session without authenticating to the system. When the sticky keys are "activated" the privilleged shell is launched.

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html
* https://www.clearskysec.com/wp-content/uploads/2020/02/ClearSky-Fox-Kitten-Campaign-v1.pdf


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_sticky_keys_unauthenticated_privileged_cmd_access.yml))
```yaml
title: Using Sticky-keys To Obtain Unauthenticated, Privileged Console Access
id: 1070db9a-3e5d-412e-8e7b-7183b616e1b3
description: By replacing the sticky keys executable with the local admins CMD executable, an attacker is able to access a privileged windows console session without authenticating to the system. When the sticky keys are "activated" the privilleged shell is launched.
references:
    - https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html
    - https://www.clearskysec.com/wp-content/uploads/2020/02/ClearSky-Fox-Kitten-Campaign-v1.pdf
status: experimental
date: 2020/02/18
modified: 2022/01/11
author: Sreeman
tags:
    - attack.t1546.008
    - attack.privilege_escalation
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine: 'copy /y C:\windows\system32\cmd.exe C:\windows\system32\sethc.exe'
    condition: selection
fields:
    - CommandLine
    - ParentProcess
falsepositives:
    - Unknown
level: medium

```
