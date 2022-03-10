---
title: "Okta Application Modified or Deleted"
aliases:
  - "/rule/7899144b-e416-4c28-b0b5-ab8f9e0a541d"


tags:
  - attack.impact



status: experimental





date: Sun, 12 Sep 2021 19:17:00 -0500


---

Detects when an application is modified or deleted.

<!--more-->


## Known false-positives

* Unknown



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_application_modified_or_deleted.yml))
```yaml
title: Okta Application Modified or Deleted
id: 7899144b-e416-4c28-b0b5-ab8f9e0a541d
description: Detects when an application is modified or deleted.
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
            - application.lifecycle.update
            - application.lifecycle.delete
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Unknown
 

```
