---
title: "Access to ADMIN$ Share"
aliases:
  - "/rule/098d7118-55bc-4912-a836-dc6483a8d150"

tags:
  - attack.lateral_movement
  - attack.t1077
  - attack.t1021.002



status: experimental



level: low



date: Tue, 14 Mar 2017 12:51:50 +0100


---

Detects access to $ADMIN share

<!--more-->


## Known false-positives

* Legitimate administrative activity




## Raw rule
```yaml
title: Access to ADMIN$ Share
id: 098d7118-55bc-4912-a836-dc6483a8d150
description: Detects access to $ADMIN share
tags:
    - attack.lateral_movement
    - attack.t1077          # an old one
    - attack.t1021.002
status: experimental
author: Florian Roth
date: 2017/03/04
modified: 2020/08/23
logsource:
    product: windows
    service: security
    definition: 'The advanced audit policy setting "Object Access > Audit File Share" must be configured for Success/Failure'
detection:
    selection:
        EventID: 5140
        ShareName: Admin$
    filter:
        SubjectUserName: '*$'
    condition: selection and not filter
falsepositives:
    - Legitimate administrative activity
level: low

```
