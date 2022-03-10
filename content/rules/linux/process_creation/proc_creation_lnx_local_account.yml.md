---
title: "Local System Accounts Discovery"
aliases:
  - "/rule/b45e3d6f-42c6-47d8-a478-df6bd6cf534c"


tags:
  - attack.discovery
  - attack.t1087.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects enumeration of local systeam accounts

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_local_account.yml))
```yaml
title: Local System Accounts Discovery
id: b45e3d6f-42c6-47d8-a478-df6bd6cf534c
status: test
description: Detects enumeration of local systeam accounts
author: Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1087.001/T1087.001.md
date: 2020/10/08
modified: 2021/11/27
logsource:
  category: process_creation
  product: linux
detection:
  selection_1:
    Image|endswith:
      - '/lastlog'
  selection_2:
    CommandLine|contains:
      - '''x:0:'''
  selection_3:
    Image|endswith:
      - '/cat'
    CommandLine|contains:
      - '/etc/passwd'
      - '/etc/sudoers'
  selection_4:
    Image|endswith:
      - '/id'
  selection_5:
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
