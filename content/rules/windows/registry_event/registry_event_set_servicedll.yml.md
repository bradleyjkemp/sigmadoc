---
title: "ServiceDll Modification"
aliases:
  - "/rule/612e47e9-8a59-43a6-b404-f48683f45bd6"
ruleid: 612e47e9-8a59-43a6-b404-f48683f45bd6

tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003



status: experimental





date: Fri, 4 Feb 2022 10:49:50 +0100


---

Detects the modification of a ServiceDLL value in the service settings

<!--more-->


## Known false-positives

* Administrative scripts
* Installation of a service



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md#atomic-test-4---tinyturla-backdoor-service-w64time


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_set_servicedll.yml))
```yaml
title: ServiceDll Modification
id: 612e47e9-8a59-43a6-b404-f48683f45bd6
description: Detects the modification of a ServiceDLL value in the service settings
author: frack113
date: 2022/02/04
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1543.003/T1543.003.md#atomic-test-4---tinyturla-backdoor-service-w64time
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject|startswith: 'HKLM\System\CurrentControlSet\Services\'
        TargetObject|endswith: '\Parameters\ServiceDll'
    condition: selection
falsepositives:
    - Administrative scripts
    - Installation of a service
level: medium
tags:
  - attack.persistence
  - attack.privilege_escalation
  - attack.t1543.003

```
