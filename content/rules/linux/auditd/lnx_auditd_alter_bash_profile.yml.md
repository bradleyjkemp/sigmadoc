---
title: "Edit of .bash_profile and .bashrc"
aliases:
  - "/rule/e74e15cc-c4b6-4c80-b7eb-dfe49feb7fe9"

tags:
  - attack.s0003
  - attack.t1156
  - attack.persistence
  - attack.t1546.004



date: Sun, 12 May 2019 02:07:13 +0200


---

Detects change of user environment. Adversaries can insert code into these files to gain persistence each time a user logs in or opens a new shell.

<!--more-->


## Known false-positives

* Admin or User activity



## References

* MITRE Attack technique T1156; .bash_profile and .bashrc. 


## Raw rule
```yaml
title: Edit of .bash_profile and .bashrc
id: e74e15cc-c4b6-4c80-b7eb-dfe49feb7fe9
status: experimental
description: Detects change of user environment. Adversaries can insert code into these files to gain persistence each time a user logs in or opens a new shell.
author: Peter Matkovski
date: 2019/05/12
references:
    - 'MITRE Attack technique T1156; .bash_profile and .bashrc. '
logsource:
    product: linux
    service: auditd
detection:
    selection:
        type: 'PATH'
        name:
            - '/home/*/.bashrc'
            - '/home/*/.bash_profile'
            - '/home/*/.profile'
            - '/etc/profile'
            - '/etc/shells'
            - '/etc/bashrc'
            - '/etc/csh.cshrc'
            - '/etc/csh.login'
    condition: selection
falsepositives:
    - Admin or User activity
level: medium
tags:
    - attack.s0003
    - attack.t1156    # an old one
    - attack.persistence
    - attack.t1546.004
```