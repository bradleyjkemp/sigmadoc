---
title: "Office Security Settings Changed"
aliases:
  - "/rule/a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd"

tags:
  - attack.defense_evasion
  - attack.t1112



status: experimental



level: high



date: Wed, 3 Jun 2020 17:40:05 -0400


---

Detects registry changes to Office macro settings

<!--more-->


## Known false-positives

* Valid Macros and/or internal documents



## References

* Internal Research


## Raw rule
```yaml
title: Office Security Settings Changed
id: a166f74e-bf44-409d-b9ba-ea4b2dd8b3cd
status: experimental
description: Detects registry changes to Office macro settings
author: Trent Liffick (@tliffick)
date: 2020/05/22
modified: 2020/07/01
references:
    - Internal Research
tags:
    - attack.defense_evasion
    - attack.t1112
logsource:
    category: registry_event
    product: windows
detection:
    sec_settings:
        TargetObject|endswith:
            - '*\Security\Trusted Documents\TrustRecords'
            - '*\Security\AccessVBOM'
            - '*\Security\VBAWarnings'
        EventType:
            - SetValue
            - DeleteValue
            - CreateValue
    condition: sec_settings
falsepositives:
    - Valid Macros and/or internal documents
level: high
```
