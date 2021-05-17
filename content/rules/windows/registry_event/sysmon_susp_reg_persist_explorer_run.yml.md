---
title: "Registry Persistence via Explorer Run Key"
aliases:
  - "/rule/b7916c2a-fa2f-4795-9477-32b731f70f11"

tags:
  - attack.persistence
  - attack.t1060
  - attack.t1547.001
  - capec.270



status: experimental



level: high



date: Thu, 19 Jul 2018 16:21:50 -0600


---

Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder

<!--more-->


## Known false-positives

* Unknown



## References

* https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/


## Raw rule
```yaml
title: Registry Persistence via Explorer Run Key
id: b7916c2a-fa2f-4795-9477-32b731f70f11
status: experimental
description: Detects a possible persistence mechanism using RUN key for Windows Explorer and pointing to a suspicious folder
author: Florian Roth
date: 2018/07/18
modified: 2020/09/06
references:
    - https://researchcenter.paloaltonetworks.com/2018/07/unit42-upatre-continues-evolve-new-anti-analysis-techniques/
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        TargetObject: '*\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
        Details: 
            - 'C:\Windows\Temp\\*'
            - 'C:\ProgramData\\*'
            - '*\AppData\\*'
            - 'C:\$Recycle.bin\\*'
            - 'C:\Temp\\*'
            - 'C:\Users\Public\\*'
            - 'C:\Users\Default\\*'
    condition: selection
tags:
    - attack.persistence
    - attack.t1060 # an old one
    - attack.t1547.001
    - capec.270
fields:
    - Image
    - ParentImage
falsepositives:
    - Unknown
level: high

```
