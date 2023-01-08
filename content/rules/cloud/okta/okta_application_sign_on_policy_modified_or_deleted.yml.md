---
title: "Okta Application Sign-On Policy Modified or Deleted"
aliases:
  - "/rule/8f668cc4-c18e-45fe-ad00-624a981cf88a"
ruleid: 8f668cc4-c18e-45fe-ad00-624a981cf88a

tags:
  - attack.impact



status: experimental





date: Sun, 12 Sep 2021 19:17:00 -0500


---

Detects when an application Sign-on Policy is modified or deleted.

<!--more-->


## Known false-positives

* Unknown



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_application_sign_on_policy_modified_or_deleted.yml))
```yaml
title: Okta Application Sign-On Policy Modified or Deleted
id: 8f668cc4-c18e-45fe-ad00-624a981cf88a
description: Detects when an application Sign-on Policy is modified or deleted.
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
            - application.policy.sign_on.update
            - application.policy.sign_on.rule.delete
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Unknown
```
