---
title: "Pandemic Registry Key"
aliases:
  - "/rule/47e0852a-cf81-4494-a8e6-31864f8c86ed"
ruleid: 47e0852a-cf81-4494-a8e6-31864f8c86ed

tags:
  - attack.lateral_movement
  - attack.t1105



status: experimental





date: Thu, 1 Jun 2017 22:48:59 +0200


---

Detects Pandemic Windows Implant

<!--more-->


## Known false-positives

* unknown



## References

* https://wikileaks.org/vault7/#Pandemic
* https://twitter.com/MalwareJake/status/870349480356454401


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_apt_pandemic.yml))
```yaml
title: Pandemic Registry Key
id: 47e0852a-cf81-4494-a8e6-31864f8c86ed
status: experimental
description: Detects Pandemic Windows Implant
references:
    - https://wikileaks.org/vault7/#Pandemic
    - https://twitter.com/MalwareJake/status/870349480356454401
tags:
    - attack.lateral_movement
    - attack.t1105
author: Florian Roth
date: 2017/06/01
modified: 2021/09/12
logsource:
    category: registry_event
    product: windows
detection:
    selection:        
        TargetObject|contains: '\SYSTEM\CurrentControlSet\services\null\Instance'
    condition: selection
falsepositives:
    - unknown
level: critical
fields:
    - EventID
    - CommandLine
    - ParentCommandLine
    - Image
    - User
    - TargetObject
```