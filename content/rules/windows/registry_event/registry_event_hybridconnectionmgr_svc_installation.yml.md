---
title: "HybridConnectionManager Service Installation"
aliases:
  - "/rule/ac8866c7-ce44-46fd-8c17-b24acff96ca8"
ruleid: ac8866c7-ce44-46fd-8c17-b24acff96ca8

tags:
  - attack.resource_development
  - attack.t1608



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the installation of the Azure Hybrid Connection Manager service to allow remote code execution from Azure function.

<!--more-->


## Known false-positives

* Unknown



## References

* https://twitter.com/Cyb3rWard0g/status/1381642789369286662


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_hybridconnectionmgr_svc_installation.yml))
```yaml
title: HybridConnectionManager Service Installation
id: ac8866c7-ce44-46fd-8c17-b24acff96ca8
description: Detects the installation of the Azure Hybrid Connection Manager service to allow remote code execution from Azure function.
status: experimental
date: 2021/04/12
modified: 2022/01/13
author: Roberto Rodriguez (Cyb3rWard0g), OTR (Open Threat Research)
tags:
    - attack.resource_development
    - attack.t1608
references:
    - https://twitter.com/Cyb3rWard0g/status/1381642789369286662
logsource:
    category: registry_event
    product: windows
detection:
    selection1:
        TargetObject|contains: '\Services\HybridConnectionManager'
    selection2:
        EventType: SetValue 
        Details|contains: 'Microsoft.HybridConnectionManager.Listener.exe'
    condition: selection1 or selection2
falsepositives:
    - Unknown
level: high

```
