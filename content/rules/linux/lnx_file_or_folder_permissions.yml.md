---
title: "File or Folder Permissions Change"
aliases:
  - "/rule/74c01ace-0152-4094-8ae2-6fd776dd43e5"

tags:
  - attack.defense_evasion
  - attack.t1222.002



date: Wed, 23 Oct 2019 11:24:13 -0700


---

Detects file and folder permission changes

<!--more-->


## Known false-positives

* User interracting with files permissions (normal/daily behaviour)



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.002/T1222.002.yaml


## Raw rule
```yaml
title: File or Folder Permissions Change
id: 74c01ace-0152-4094-8ae2-6fd776dd43e5
status: experimental
description: Detects file and folder permission changes
author: Jakob Weinzettl, oscd.community
date: 2019/09/23
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.002/T1222.002.yaml
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'EXECVE'
        a0|contains:
            - 'chmod'
            - 'chown'
    condition: selection
falsepositives:
    - User interracting with files permissions (normal/daily behaviour)
level: low
tags:
    - attack.defense_evasion
    - attack.t1222.002
```
