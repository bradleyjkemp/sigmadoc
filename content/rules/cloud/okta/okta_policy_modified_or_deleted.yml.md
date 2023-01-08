---
title: "Okta Policy Modified or Deleted"
aliases:
  - "/rule/1667a172-ed4c-463c-9969-efd92195319a"
ruleid: 1667a172-ed4c-463c-9969-efd92195319a

tags:
  - attack.impact



status: experimental





date: Sun, 12 Sep 2021 19:13:15 -0500


---

Detects when an Okta policy is modified or deleted.

<!--more-->


## Known false-positives

* Okta Policies being modified or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Okta Policies modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_policy_modified_or_deleted.yml))
```yaml
title: Okta Policy Modified or Deleted
id: 1667a172-ed4c-463c-9969-efd92195319a
description: Detects when an Okta policy is modified or deleted.
author: Austin Songer @austinsonger
status: experimental
date: 2021/09/12
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
            - policy.lifecycle.update
            - policy.lifecycle.delete
    condition: selection
level: low
tags:
    - attack.impact
falsepositives:
 - Okta Policies being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Okta Policies modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
