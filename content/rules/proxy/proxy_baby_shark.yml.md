---
title: "BabyShark Agent Pattern"
aliases:
  - "/rule/304810ed-8853-437f-9e36-c4975c3dfd7e"
ruleid: 304810ed-8853-437f-9e36-c4975c3dfd7e

tags:
  - attack.command_and_control
  - attack.t1071.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects Baby Shark C2 Framework communication patterns

<!--more-->


## Known false-positives

* Unknown



## References

* https://nasbench.medium.com/understanding-detecting-c2-frameworks-babyshark-641be4595845


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/proxy/proxy_baby_shark.yml))
```yaml
title: BabyShark Agent Pattern
id: 304810ed-8853-437f-9e36-c4975c3dfd7e
status: experimental
description: Detects Baby Shark C2 Framework communication patterns
author: Florian Roth
date: 2021/06/09
references:
    - https://nasbench.medium.com/understanding-detecting-c2-frameworks-babyshark-641be4595845
logsource:
    category: proxy
detection:
    selection:
        c-uri|contains: 'momyshark?key='
    condition: selection
falsepositives:
    - Unknown
level: critical
tags:
    - attack.command_and_control
    - attack.t1071.001
```
