---
title: "Okta Admin Role Assigned to an User or Group"
aliases:
  - "/rule/413d4a81-6c98-4479-9863-014785fd579c"
ruleid: 413d4a81-6c98-4479-9863-014785fd579c

tags:
  - attack.impact



status: experimental





date: Sun, 12 Sep 2021 19:45:57 -0500


---

Detects when an the Administrator role is assigned to an user or group.

<!--more-->


## Known false-positives

* Administrator roles could be assigned to users or group by other admin users.



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_admin_role_assigned_to_user_or_group.yml))
```yaml
title: Okta Admin Role Assigned to an User or Group
id: 413d4a81-6c98-4479-9863-014785fd579c
description: Detects when an the Administrator role is assigned to an user or group.
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
            - group.privilege.grant
            - user.account.privilege.grant
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Administrator roles could be assigned to users or group by other admin users. 
 

```
