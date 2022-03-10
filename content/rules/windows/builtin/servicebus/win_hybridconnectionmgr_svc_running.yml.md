---
title: "HybridConnectionManager Service Running"
aliases:
  - "/rule/b55d23e5-6821-44ff-8a6e-67218891e49f"


tags:
  - attack.persistence
  - attack.t1554



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Rule to detect the Hybrid Connection Manager service running on an endpoint.

<!--more-->


## Known false-positives

* Legitimate use of Hybrid Connection Manager via Azure function apps.



## References

* https://twitter.com/Cyb3rWard0g/status/1381642789369286662


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/servicebus/win_hybridconnectionmgr_svc_running.yml))
```yaml
title: HybridConnectionManager Service Running
id: b55d23e5-6821-44ff-8a6e-67218891e49f
description: Rule to detect the Hybrid Connection Manager service running on an endpoint.
status: experimental
date: 2021/04/12
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.persistence
    - attack.t1554 
references:
    - https://twitter.com/Cyb3rWard0g/status/1381642789369286662
logsource:
    product: windows
    service: microsoft-servicebus-client
detection:
    selection:
        EventID:
            - 40300
            - 40301
            - 40302
    keywords:
        - 'HybridConnection'
        - 'sb://'
        - 'servicebus.windows.net'
        - 'HybridConnectionManage'
    condition: selection and keywords
falsepositives:
    - Legitimate use of Hybrid Connection Manager via Azure function apps.
level: high

```
