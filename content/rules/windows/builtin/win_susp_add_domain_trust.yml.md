---
title: "Addition of Domain Trusts"
aliases:
  - "/rule/0255a820-e564-4e40-af2b-6ac61160335c"

tags:
  - attack.persistence



date: Tue, 3 Dec 2019 14:28:20 +0100


---

Addition of domains is seldom and should be verified for legitimacy.

<!--more-->


## Known false-positives

* Legitimate extension of domain structure




## Raw rule
```yaml
title: Addition of Domain Trusts
id: 0255a820-e564-4e40-af2b-6ac61160335c
status: stable
description: Addition of domains is seldom and should be verified for legitimacy.
author: Thomas Patzke
date: 2019/12/03
tags:
    - attack.persistence
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4706
    condition: selection
falsepositives:
    - Legitimate extension of domain structure
level: medium

```
