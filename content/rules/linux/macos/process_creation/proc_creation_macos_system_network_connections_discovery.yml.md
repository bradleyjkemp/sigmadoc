---
title: "System Network Connections Discovery"
aliases:
  - "/rule/9a7a0393-2144-4626-9bf1-7c2f5a7321db"
ruleid: 9a7a0393-2144-4626-9bf1-7c2f5a7321db

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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_system_network_connections_discovery.yml))
```yaml
title: System Network Connections Discovery
id: 9a7a0393-2144-4626-9bf1-7c2f5a7321db
status: test
description: Detects usage of system utilities to discover system network connections
author: Daniil Yugoslavskiy, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md
date: 2020/10/19
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  selection:
    Image:
      - '/usr/bin/who'
      - '/usr/bin/w'
      - '/usr/bin/last'
      - '/usr/sbin/lsof'
      - '/usr/sbin/netstat'
  condition: selection
falsepositives:
  - Legitimate activities
level: informational
tags:
  - attack.discovery
  - attack.t1049

```
