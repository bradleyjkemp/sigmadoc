---
title: "HybridConnectionManager Service Installation"
aliases:
  - "/rule/0ee4d8a5-4e67-4faf-acfa-62a78457d1f2"


tags:
  - attack.persistence
  - attack.t1554



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Rule to detect the Hybrid Connection Manager service installation.

<!--more-->


## Known false-positives

* Legitimate use of Hybrid Connection Manager via Azure function apps.



## References

* https://twitter.com/Cyb3rWard0g/status/1381642789369286662


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_hybridconnectionmgr_svc_installation.yml))
```yaml
title: HybridConnectionManager Service Installation
id: 0ee4d8a5-4e67-4faf-acfa-62a78457d1f2
description: Rule to detect the Hybrid Connection Manager service installation.
status: experimental
date: 2021/04/12
modified: 2021/08/09
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.persistence
    - attack.t1554 
references:
    - https://twitter.com/Cyb3rWard0g/status/1381642789369286662
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4697
        ServiceName: HybridConnectionManager
        ServiceFileName|contains: HybridConnectionManager 
    condition: selection
falsepositives:
    - Legitimate use of Hybrid Connection Manager via Azure function apps.
level: high

```
