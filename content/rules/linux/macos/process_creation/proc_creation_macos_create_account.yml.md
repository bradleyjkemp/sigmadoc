---
title: "Creation Of A Local User Account"
aliases:
  - "/rule/51719bf5-e4fd-4e44-8ba8-b830e7ac0731"


tags:
  - attack.t1136.001
  - attack.persistence



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the creation of a new user account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_create_account.yml))
```yaml
title: Creation Of A Local User Account
id: 51719bf5-e4fd-4e44-8ba8-b830e7ac0731
status: test
description: Detects the creation of a new user account. Such accounts may be used for persistence that do not require persistent remote access tools to be deployed on the system.
author: Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1136.001/T1136.001.md
date: 2020/10/06
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  selection:
    Image|endswith:
      - '/dscl'
    CommandLine|contains:
      - 'create'
  condition: selection
falsepositives:
  - Legitimate administration activities
level: low
tags:
  - attack.t1136.001
  - attack.persistence

```
