---
title: "Hidden Local User Creation"
aliases:
  - "/rule/7b449a5e-1db5-4dd0-a2dc-4e3a67282538"


tags:
  - attack.persistence
  - attack.t1136.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the creation of a local hidden user account which should not happen for event ID 4720.

<!--more-->


## Known false-positives

* unknown



## References

* https://twitter.com/SBousseaden/status/1387743867663958021


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_hidden_user_creation.yml))
```yaml
title: Hidden Local User Creation
id: 7b449a5e-1db5-4dd0-a2dc-4e3a67282538
description: Detects the creation of a local hidden user account which should not happen for event ID 4720.
status: experimental
tags:
    - attack.persistence
    - attack.t1136.001
references:
  - https://twitter.com/SBousseaden/status/1387743867663958021
author: Christian Burkard
date: 2021/05/03
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4720
        TargetUserName|endswith: '$'
    condition: selection
fields:
    - EventCode
    - AccountName
falsepositives:
    - unknown
level: high

```
