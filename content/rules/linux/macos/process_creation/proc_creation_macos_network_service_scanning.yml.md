---
title: "MacOS Network Service Scanning"
aliases:
  - "/rule/84bae5d4-b518-4ae0-b331-6d4afd34d00f"


tags:
  - attack.discovery
  - attack.t1046



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects enumeration of local or remote network services.

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/macos/process_creation/proc_creation_macos_network_service_scanning.yml))
```yaml
title: MacOS Network Service Scanning
id: 84bae5d4-b518-4ae0-b331-6d4afd34d00f
status: test
description: Detects enumeration of local or remote network services.
author: Alejandro Ortuno, oscd.community
references:
  - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1046/T1046.md
date: 2020/10/21
modified: 2021/11/27
logsource:
  category: process_creation
  product: macos
detection:
  selection_1:
    Image|endswith:
      - '/nc'
      - '/netcat'
  selection_2:
    Image|endswith:
      - '/nmap'
      - '/telnet'
  filter:
    CommandLine|contains: 'l'
  condition: (selection_1 and not filter) or selection_2
falsepositives:
  - Legitimate administration activities
level: low
tags:
  - attack.discovery
  - attack.t1046

```
