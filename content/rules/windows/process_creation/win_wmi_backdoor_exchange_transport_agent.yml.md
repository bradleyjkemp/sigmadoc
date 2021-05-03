---
title: "WMI Backdoor Exchange Transport Agent"
aliases:
  - "/rule/797011dc-44f4-4e6f-9f10-a8ceefbe566b"

tags:
  - attack.persistence
  - attack.t1546.003
  - attack.t1084



date: Fri, 11 Oct 2019 12:12:30 +0200


---

Detects a WMi backdoor in Exchange Transport Agents via WMi event filters

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/cglyer/status/1182389676876980224
* https://twitter.com/cglyer/status/1182391019633029120


## Raw rule
```yaml
title: WMI Backdoor Exchange Transport Agent
id: 797011dc-44f4-4e6f-9f10-a8ceefbe566b
status: experimental
description: Detects a WMi backdoor in Exchange Transport Agents via WMi event filters
author: Florian Roth
date: 2019/10/11
references:
    - https://twitter.com/cglyer/status/1182389676876980224
    - https://twitter.com/cglyer/status/1182391019633029120
logsource:
    category: process_creation
    product: windows
tags:
    - attack.persistence
    - attack.t1546.003
    - attack.t1084      # an old one
detection:
    selection:
        ParentImage: '*\EdgeTransport.exe'
    condition: selection
falsepositives:
    - Unknown
level: critical


```
