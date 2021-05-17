---
title: "WMI Event Subscription"
aliases:
  - "/rule/0f06a3a5-6a09-413f-8743-e6cf35561297"

tags:
  - attack.t1084
  - attack.persistence
  - attack.t1546.003



status: experimental



level: high



date: Sat, 12 Jan 2019 12:02:26 +0100


---

Detects creation of WMI event subscription persistence method

<!--more-->


## Known false-positives

* exclude legitimate (vetted) use of WMI event subscription in your network




## Raw rule
```yaml
title: WMI Event Subscription
id: 0f06a3a5-6a09-413f-8743-e6cf35561297
status: experimental
description: Detects creation of WMI event subscription persistence method
tags:
    - attack.t1084          # an old one
    - attack.persistence
    - attack.t1546.003
author: Tom Ueltschi (@c_APT_ure)
date: 2019/01/12
logsource:
    product: windows
    service: sysmon
detection:
    selector:
        EventID:
            - 19
            - 20
            - 21
    condition: selector
falsepositives:
    - exclude legitimate (vetted) use of WMI event subscription in your network
level: high

```
