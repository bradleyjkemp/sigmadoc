---
title: "Scheduled Task/Job At"
aliases:
  - "/rule/d2d642d7-b393-43fe-bae4-e81ed5915c4b"
ruleid: d2d642d7-b393-43fe-bae4-e81ed5915c4b

tags:
  - attack.persistence
  - attack.t1053.001



status: stable





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the use of at/atd

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.001/T1053.001.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_at_command.yml))
```yaml
title: Scheduled Task/Job At
id: d2d642d7-b393-43fe-bae4-e81ed5915c4b
status: stable
description: Detects the use of at/atd
author: Ömer Günal, oscd.community
date: 2020/10/06
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1053.001/T1053.001.md
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
          - '/at'
          - '/atd'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: low
tags:
    - attack.persistence
    - attack.t1053.001

```
