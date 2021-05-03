---
title: "Creation Of An User Account"
aliases:
  - "/rule/759d0d51-bc99-4b5e-9add-8f5b2c8e7512"

tags:
  - attack.t1136
  - attack.t1136.001
  - attack.persistence



date: Fri, 5 Jun 2020 13:18:03 -0400


---

Detects the creation of a new user account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

<!--more-->


## Known false-positives

* Admin activity



## References

* MITRE Attack technique T1136; Create Account 


## Raw rule
```yaml
title: Creation Of An User Account
id: 759d0d51-bc99-4b5e-9add-8f5b2c8e7512
status: experimental
description: Detects the creation of a new user account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.
author: Marie Euler
date: 2020/05/18
references:
    - 'MITRE Attack technique T1136; Create Account '
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'SYSCALL'
        exe: '*/useradd'
    condition: selection
falsepositives:
    - Admin activity
level: medium
tags:
    - attack.t1136    # an old one
    - attack.t1136.001
    - attack.persistence
```
