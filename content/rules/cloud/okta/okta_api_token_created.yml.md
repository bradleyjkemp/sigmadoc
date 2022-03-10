---
title: "Okta API Token Created"
aliases:
  - "/rule/19951c21-229d-4ccb-8774-b993c3ff3c5c"


tags:
  - attack.persistence



status: experimental





date: Sun, 12 Sep 2021 19:17:00 -0500


---

Detects when a API token is created

<!--more-->


## Known false-positives

* Unknown



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_api_token_created.yml))
```yaml
title: Okta API Token Created
id: 19951c21-229d-4ccb-8774-b993c3ff3c5c
description: Detects when a API token is created
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
        eventtype: system.api_token.create
    condition: selection
level: medium
tags:
    - attack.persistence
falsepositives:
 - Unknown


```
