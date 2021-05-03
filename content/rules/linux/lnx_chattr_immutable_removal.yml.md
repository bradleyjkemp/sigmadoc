---
title: "Remove Immutable File Attribute"
aliases:
  - "/rule/a5b977d6-8a81-4475-91b9-49dbfcd941f7"

tags:
  - attack.defense_evasion
  - attack.t1222.002



date: Wed, 23 Oct 2019 11:24:13 -0700


---

Detects removing immutable file attribute

<!--more-->


## Known false-positives

* Administrator interacting with immutable files (for instance backups)



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1222.002/T1222.002.yaml


## Raw rule
```yaml
title: Remove Immutable File Attribute
id: a5b977d6-8a81-4475-91b9-49dbfcd941f7
status: experimental
description: Detects removing immutable file attribute
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
        a0|contains: 'chattr'
        a1|contains: '-i'
    condition: selection
falsepositives:
    - Administrator interacting with immutable files (for instance backups)
level: medium
tags:
    - attack.defense_evasion
    - attack.t1222.002
```