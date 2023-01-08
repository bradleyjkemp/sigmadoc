---
title: "Okta User Account Locked Out"
aliases:
  - "/rule/14701da0-4b0f-4ee6-9c95-2ffb4e73bb9a"
ruleid: 14701da0-4b0f-4ee6-9c95-2ffb4e73bb9a

tags:
  - attack.impact



status: experimental





date: Sun, 12 Sep 2021 19:35:19 -0500


---

Detects when an user account is locked out.

<!--more-->


## Known false-positives

* Unknown



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_user_account_locked_out.yml))
```yaml
title: Okta User Account Locked Out
id: 14701da0-4b0f-4ee6-9c95-2ffb4e73bb9a
description: Detects when an user account is locked out.
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
        displaymessage: Max sign in attempts exceeded
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Unknown

```
