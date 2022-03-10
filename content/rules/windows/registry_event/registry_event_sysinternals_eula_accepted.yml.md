---
title: "Usage of Sysinternals Tools"
aliases:
  - "/rule/25ffa65d-76d8-4da5-a832-3f2b0136e133"


tags:
  - attack.resource_development
  - attack.t1588.002



status: experimental





date: Tue, 28 Aug 2018 17:36:22 +0200


---

Detects the usage of Sysinternals Tools due to accepteula key being added to Registry

<!--more-->


## Known false-positives

* Legitimate use of SysInternals tools
* Programs that use the same Registry Key



## References

* https://twitter.com/Moti_B/status/1008587936735035392


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_sysinternals_eula_accepted.yml))
```yaml
title: Usage of Sysinternals Tools
id: 25ffa65d-76d8-4da5-a832-3f2b0136e133
status: experimental
description: Detects the usage of Sysinternals Tools due to accepteula key being added to Registry
references:
    - https://twitter.com/Moti_B/status/1008587936735035392
date: 2017/08/28
modified: 2021/09/12
author: Markus Neis
tags:
    - attack.resource_development 
    - attack.t1588.002 
logsource:
    product: windows
    category: registry_event
detection:
    selection:
        TargetObject|endswith: '\EulaAccepted'
    condition: selection
falsepositives:
    - Legitimate use of SysInternals tools
    - Programs that use the same Registry Key
level: low
```
