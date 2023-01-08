---
title: "OneLogin User Assumed Another User"
aliases:
  - "/rule/62fff148-278d-497e-8ecd-ad6083231a35"
ruleid: 62fff148-278d-497e-8ecd-ad6083231a35

tags:
  - attack.impact



status: experimental





date: Mon, 11 Oct 2021 21:03:48 -0500


---

Detects when an user assumed another user account.

<!--more-->


## Known false-positives

* Unknown



## References

* https://developers.onelogin.com/api-docs/1/events/event-resource


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/onelogin/onelogin_assumed_another_user.yml))
```yaml
title: OneLogin User Assumed Another User
id: 62fff148-278d-497e-8ecd-ad6083231a35
description: Detects when an user assumed another user account.
author: Austin Songer @austinsonger
status: experimental
date: 2021/10/12
modified: 2021/10/12
references:
    - https://developers.onelogin.com/api-docs/1/events/event-resource
logsource:
  product: onelogin
  service: onelogin.events
detection:
    selection:
        event_type_id: 3
    condition: selection
level: low
tags:
    - attack.impact
falsepositives:
 - Unknown

```
