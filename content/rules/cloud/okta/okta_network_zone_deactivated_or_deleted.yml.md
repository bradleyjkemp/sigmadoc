---
title: "Okta Network Zone Deactivated or Deleted"
aliases:
  - "/rule/9f308120-69ed-4506-abde-ac6da81f4310"
ruleid: 9f308120-69ed-4506-abde-ac6da81f4310

tags:
  - attack.impact



status: experimental





date: Sun, 12 Sep 2021 19:22:15 -0500


---

Detects when an Network Zone is Deactivated or Deleted.

<!--more-->


## Known false-positives

* Unknown



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_network_zone_deactivated_or_deleted.yml))
```yaml
title: Okta Network Zone Deactivated or Deleted
id: 9f308120-69ed-4506-abde-ac6da81f4310
description: Detects when an Network Zone is Deactivated or Deleted.
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
            - zone.deactivate
            - zone.delete
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Unknown
 

```
