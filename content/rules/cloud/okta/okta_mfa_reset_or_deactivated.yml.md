---
title: "Okta MFA Reset or Deactivated"
aliases:
  - "/rule/50e068d7-1e6b-4054-87e5-0a592c40c7e0"
ruleid: 50e068d7-1e6b-4054-87e5-0a592c40c7e0

tags:
  - attack.persistence



status: experimental





date: Sun, 12 Sep 2021 20:40:33 -0500


---

Detects when an attempt at deactivating  or resetting MFA.

<!--more-->


## Known false-positives

* If a MFA reset or deactivated was performed by a system administrator.



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_mfa_reset_or_deactivated.yml))
```yaml
title: Okta MFA Reset or Deactivated
id: 50e068d7-1e6b-4054-87e5-0a592c40c7e0
description: Detects when an attempt at deactivating  or resetting MFA.
author: Austin Songer @austinsonger
status: experimental
date: 2021/09/21
modified: 2021/09/22
references:
    - https://developer.okta.com/docs/reference/api/system-log/
    - https://developer.okta.com/docs/reference/api/event-types/
logsource:
  product: okta
  service: okta
detection:
    selection:
        eventtype: 
            - user.mfa.factor.deactivate
            - user.mfa.factor.reset_all
    condition: selection
level: medium
tags:
    - attack.persistence
falsepositives:
 - If a MFA reset or deactivated was performed by a system administrator. 

```
