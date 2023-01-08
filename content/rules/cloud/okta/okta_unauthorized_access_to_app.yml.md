---
title: "Okta Unauthorized Access to App"
aliases:
  - "/rule/6cc2b61b-d97e-42ef-a9dd-8aa8dc951657"
ruleid: 6cc2b61b-d97e-42ef-a9dd-8aa8dc951657

tags:
  - attack.impact



status: experimental





date: Sun, 12 Sep 2021 19:35:19 -0500


---

Detects when unauthorized access to app occurs.

<!--more-->


## Known false-positives

* User might of believe that they had access.



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_unauthorized_access_to_app.yml))
```yaml
title: Okta Unauthorized Access to App
id: 6cc2b61b-d97e-42ef-a9dd-8aa8dc951657
description: Detects when unauthorized access to app occurs.
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
        displaymessage:
            - User attempted unauthorized access to app
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - User might of believe that they had access.

```
