---
title: "Local System Accounts Discovery"
aliases:
  - "/rule/ddf36b67-e872-4507-ab2e-46bda21b842c"
ruleid: ddf36b67-e872-4507-ab2e-46bda21b842c

tags:
  - attack.discovery
  - attack.t1087.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects enumeration of local systeam accounts on MacOS

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_local_account.yml))
```yaml
title: Local System Accounts Discovery
id: ddf36b67-e872-4507-ab2e-46bda21b842c
status: test
description: Detects enumeration of local systeam accounts on MacOS
author: Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md
date: 2020/10/08
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  selection_1:
    Image|endswith:
      - '/dscl'
    CommandLine|contains|all:
      - 'list'
      - '/users'
  selection_2:
    Image|endswith:
      - '/dscacheutil'
    CommandLine|contains|all:
      - '-q'
      - 'user'
  selection_3:
    CommandLine|contains:
      - '''x:0:'''
  selection_4:
    Image|endswith:
      - '/cat'
    CommandLine|contains:
      - '/etc/passwd'
      - '/etc/sudoers'
  selection_5:
    Image|endswith:
      - '/id'
  selection_6:
    Image|endswith:
      - '/lsof'
    CommandLine|contains:
      - '-u'
  condition: 1 of selection*
falsepositives:
  - Legitimate administration activities
level: low
tags:
  - attack.discovery
  - attack.t1087.001

```
