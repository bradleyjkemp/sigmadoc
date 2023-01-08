---
title: "Local Groups Discovery"
aliases:
  - "/rule/89bb1f97-c7b9-40e8-b52b-7d6afbd67276"
ruleid: 89bb1f97-c7b9-40e8-b52b-7d6afbd67276

tags:
  - attack.discovery
  - attack.t1069.001



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects enumeration of local system groups

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_local_groups.yml))
```yaml
title: Local Groups Discovery
id: 89bb1f97-c7b9-40e8-b52b-7d6afbd67276
status: test
description: Detects enumeration of local system groups
author: Ömer Günal, Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md
date: 2020/10/11
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  selection_1:
    Image|endswith:
      - '/dscacheutil'
    CommandLine|contains|all:
      - '-q'
      - 'group'
  selection_2:
    Image|endswith:
      - '/cat'
    CommandLine|contains:
      - '/etc/group'
  selection_3:
    Image|endswith:
      - '/dscl'
    CommandLine|contains|all:
      - '-list'
      - '/groups'
  condition: 1 of selection*
falsepositives:
  - Legitimate administration activities
level: informational
tags:
  - attack.discovery
  - attack.t1069.001

```
