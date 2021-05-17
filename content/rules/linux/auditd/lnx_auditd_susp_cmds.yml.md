---
title: "Suspicious Commands Linux"
aliases:
  - "/rule/1543ae20-cbdf-4ec1-8d12-7664d667a825"

tags:
  - attack.execution
  - attack.t1059.004



status: experimental



level: medium



date: Tue, 23 Jan 2018 11:12:39 +0100


---

Detects relevant commands often related to malware or hacking activity

<!--more-->


## Known false-positives

* Admin activity



## References

* Internal Research - mostly derived from exploit code including code in MSF


## Raw rule
```yaml
title: Suspicious Commands Linux
id: 1543ae20-cbdf-4ec1-8d12-7664d667a825
status: experimental
description: Detects relevant commands often related to malware or hacking activity
author: Florian Roth
date: 2017/12/12
references:
    - Internal Research - mostly derived from exploit code including code in MSF
logsource:
    product: linux
    service: auditd
detection:
    cmd1:
        type: 'EXECVE'
        a0: 'chmod'
        a1: '777'
    cmd2:
        type: 'EXECVE'
        a0: 'chmod'
        a1: 'u+s'
    cmd3:
        type: 'EXECVE'
        a0: 'cp'
        a1: '/bin/ksh'
    cmd4:
        type: 'EXECVE'
        a0: 'cp'
        a1: '/bin/sh'
    condition: 1 of them
falsepositives:
    - Admin activity
level: medium
tags:
    - attack.execution
    - attack.t1059.004
```
