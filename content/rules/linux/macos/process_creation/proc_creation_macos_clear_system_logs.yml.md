---
title: "Indicator Removal on Host - Clear Mac System Logs"
aliases:
  - "/rule/acf61bd8-d814-4272-81f0-a7a269aa69aa"
ruleid: acf61bd8-d814-4272-81f0-a7a269aa69aa

tags:
  - attack.defense_evasion
  - attack.t1070.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects deletion of local audit logs

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_clear_system_logs.yml))
```yaml
title: Indicator Removal on Host - Clear Mac System Logs
id: acf61bd8-d814-4272-81f0-a7a269aa69aa
status: experimental
description: Detects deletion of local audit logs
author: remotephone, oscd.community
date: 2020/10/11
modified: 2021/11/11
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1070.002/T1070.002.md
logsource:
    product: macos
    category: process_creation
detection:
    selection1:
        Image|endswith: '/rm'
    selection2:
        CommandLine|contains: '/var/log'
    selection3:
        CommandLine|contains|all:
            - '/Users/'
            - '/Library/Logs/'
    condition: selection1 and (selection2 or selection3)
falsepositives:
    - Legitimate administration activities
level: medium
tags:
    - attack.defense_evasion
    - attack.t1070.002

```
