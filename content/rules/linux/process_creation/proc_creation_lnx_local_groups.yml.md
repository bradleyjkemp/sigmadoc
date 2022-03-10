---
title: "Local Groups Discovery"
aliases:
  - "/rule/676381a6-15ca-4d73-a9c8-6a22e970b90d"


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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_local_groups.yml))
```yaml
title: Local Groups Discovery
id: 676381a6-15ca-4d73-a9c8-6a22e970b90d
status: test
description: Detects enumeration of local system groups
author: Ömer Günal, Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1069.001/T1069.001.md
date: 2020/10/11
modified: 2021/11/27
logsource:
  category: process_creation
  product: linux
detection:
  selection_1:
    Image|endswith:
      - '/groups'
  selection_2:
    Image|endswith:
      - '/cat'
    CommandLine|contains:
      - '/etc/group'
  condition: 1 of selection*
falsepositives:
  - Legitimate administration activities
level: low
tags:
  - attack.discovery
  - attack.t1069.001

```
