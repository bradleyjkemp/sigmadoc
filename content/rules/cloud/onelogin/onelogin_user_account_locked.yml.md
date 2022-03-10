---
title: "OneLogin User Account Locked"
aliases:
  - "/rule/a717c561-d117-437e-b2d9-0118a7035d01"


tags:
  - attack.impact



status: experimental





date: Mon, 11 Oct 2021 21:03:48 -0500


---

Detects when an user acount is locked or suspended.

<!--more-->


## Known false-positives

* System may lock or suspend user accounts.



## References

* https://developers.onelogin.com/api-docs/1/events/event-resource/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/onelogin/onelogin_user_account_locked.yml))
```yaml
title: OneLogin User Account Locked
id: a717c561-d117-437e-b2d9-0118a7035d01
description: Detects when an user acount is locked or suspended.
author: Austin Songer @austinsonger
status: experimental
date: 2021/10/12
modified: 2021/10/12
references:
    - https://developers.onelogin.com/api-docs/1/events/event-resource/
logsource:
  product: onelogin
  service: onelogin.events
detection:
    selection1: # Locked via API
        event_type_id: 532
    selection2: # Locked via API
        event_type_id: 553
    selection3: # Suspended via API
        event_type_id: 551
    condition: 1 of selection*
level: low
tags:
    - attack.impact
falsepositives:
 - System may lock or suspend user accounts.

```
