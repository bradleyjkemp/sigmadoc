---
title: "Data Compressed - Powershell"
aliases:
  - "/rule/6dc5d284-69ea-42cf-9311-fb1c3932a69a"

tags:
  - attack.exfiltration
  - attack.t1560
  - attack.t1002



date: Tue, 22 Oct 2019 14:00:52 +0300


---

An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network

<!--more-->


## Known false-positives

* highly likely if archive ops are done via PS



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml


## Raw rule
```yaml
title: Data Compressed - Powershell
id: 6dc5d284-69ea-42cf-9311-fb1c3932a69a
status: experimental
description: An adversary may compress data (e.g., sensitive documents) that is collected prior to exfiltration in order to make it portable and minimize the amount of data sent over the network
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1002/T1002.yaml
logsource:
    product: windows
    service: powershell
    definition: 'Script block logging must be enabled'
detection:
    selection:
        EventID: 4104
        keywords|contains|all:
            - '-Recurse'
            - '|'
            - 'Compress-Archive'
    condition: selection
falsepositives:
    - highly likely if archive ops are done via PS
level: low
tags:
    - attack.exfiltration
    - attack.t1560
    - attack.t1002  # an old one

```