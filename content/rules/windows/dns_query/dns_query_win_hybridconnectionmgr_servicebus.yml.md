---
title: "DNS HybridConnectionManager Service Bus"
aliases:
  - "/rule/7bd3902d-8b8b-4dd4-838a-c6862d40150d"
ruleid: 7bd3902d-8b8b-4dd4-838a-c6862d40150d

tags:
  - attack.persistence
  - attack.t1554



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Azure Hybrid Connection Manager services querying the Azure service bus service

<!--more-->


## Known false-positives

* Legitimate use of Azure Hybrid Connection Manager and the Azure Service Bus service



## References

* https://twitter.com/Cyb3rWard0g/status/1381642789369286662


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/dns_query/dns_query_win_hybridconnectionmgr_servicebus.yml))
```yaml
title: DNS HybridConnectionManager Service Bus
id: 7bd3902d-8b8b-4dd4-838a-c6862d40150d
description: Detects Azure Hybrid Connection Manager services querying the Azure service bus service
status: experimental
date: 2021/04/12
modified: 2021/06/10
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.persistence
    - attack.t1554 
references:
    - https://twitter.com/Cyb3rWard0g/status/1381642789369286662
logsource:
    product: windows
    category: dns_query
detection:
    selection:
        QueryName|contains: servicebus.windows.net
        Image|contains: HybridConnectionManager
    condition: selection
falsepositives:
    - Legitimate use of Azure Hybrid Connection Manager and the Azure Service Bus service
level: high

```
