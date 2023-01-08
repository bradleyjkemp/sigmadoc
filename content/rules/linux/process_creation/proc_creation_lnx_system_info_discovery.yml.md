---
title: "System Information Discovery"
aliases:
  - "/rule/42df45e7-e6e9-43b5-8f26-bec5b39cc239"
ruleid: 42df45e7-e6e9-43b5-8f26-bec5b39cc239

tags:
  - attack.discovery
  - attack.t1082



status: stable





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects system information discovery commands

<!--more-->


## Known false-positives

* Legitimate administration activities



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/linux/process_creation/proc_creation_lnx_system_info_discovery.yml))
```yaml
title: System Information Discovery
id: 42df45e7-e6e9-43b5-8f26-bec5b39cc239
status: stable
description: Detects system information discovery commands
author: Ömer Günal, oscd.community
date: 2020/10/08
modified: 2021/09/14
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1082/T1082.md
tags:
    - attack.discovery
    - attack.t1082
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
          - '/uname'
          - '/hostname'
          - '/uptime'
          - '/lspci'
          - '/dmidecode'
          - '/lscpu'
          - '/lsmod'
    condition: selection
falsepositives:
    - Legitimate administration activities
level: informational

```
