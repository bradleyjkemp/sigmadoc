---
title: "Process Discovery"
aliases:
  - "/rule/4e2f5868-08d4-413d-899f-dc2f1508627b"
ruleid: 4e2f5868-08d4-413d-899f-dc2f1508627b

tags:
  - attack.discovery
  - attack.t1057



status: stable





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects process discovery commands

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_process_discovery.yml))
```yaml
title: Process Discovery
id: 4e2f5868-08d4-413d-899f-dc2f1508627b
status: stable
description: Detects process discovery commands
author: Ömer Günal, oscd.community
date: 2020/10/06
modified: 2021/08/14
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1057/T1057.md
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
          - '/ps'
          - '/top'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: informational
tags:
    - attack.discovery
    - attack.t1057

```
