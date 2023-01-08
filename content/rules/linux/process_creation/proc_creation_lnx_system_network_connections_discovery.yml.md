---
title: "System Network Connections Discovery"
aliases:
  - "/rule/4c519226-f0cd-4471-bd2f-6fbb2bb68a79"
ruleid: 4c519226-f0cd-4471-bd2f-6fbb2bb68a79

tags:
  - attack.discovery
  - attack.t1049



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects usage of system utilities to discover system network connections

<!--more-->


## Known false-positives

* Legitimate activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_system_network_connections_discovery.yml))
```yaml
title: System Network Connections Discovery
id: 4c519226-f0cd-4471-bd2f-6fbb2bb68a79
status: test
description: Detects usage of system utilities to discover system network connections
author: Daniil Yugoslavskiy, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md
date: 2020/10/19
modified: 2021/11/27
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - '/who'
      - '/w'
      - '/last'
      - '/lsof'
      - '/netstat'
  condition: selection
falsepositives:
  - Legitimate activities
level: low
tags:
  - attack.discovery
  - attack.t1049

```
