---
title: "Okta API Token Revoked"
aliases:
  - "/rule/cf1dbc6b-6205-41b4-9b88-a83980d2255b"
ruleid: cf1dbc6b-6205-41b4-9b88-a83980d2255b

tags:
  - attack.impact



status: experimental





date: Sun, 12 Sep 2021 19:17:00 -0500


---

Detects when a API Token is revoked.

<!--more-->


## Known false-positives

* Unknown



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_api_token_revoked.yml))
```yaml
title: Okta API Token Revoked
id: cf1dbc6b-6205-41b4-9b88-a83980d2255b
description: Detects when a API Token is revoked.
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
        eventtype: system.api_token.revoke
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Unknown
 

```
