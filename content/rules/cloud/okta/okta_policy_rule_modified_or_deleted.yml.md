---
title: "Okta Policy Rule Modified or Deleted"
aliases:
  - "/rule/0c97c1d3-4057-45c9-b148-1de94b631931"
ruleid: 0c97c1d3-4057-45c9-b148-1de94b631931

tags:
  - attack.impact



status: experimental





date: Sun, 12 Sep 2021 19:17:00 -0500


---

Detects when an Policy Rule is Modified or Deleted.

<!--more-->


## Known false-positives

* Unknown



## References

* https://developer.okta.com/docs/reference/api/system-log/
* https://developer.okta.com/docs/reference/api/event-types/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/okta/okta_policy_rule_modified_or_deleted.yml))
```yaml
title: Okta Policy Rule Modified or Deleted
id: 0c97c1d3-4057-45c9-b148-1de94b631931
description: Detects when an Policy Rule is Modified or Deleted.
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
            - policy.rule.update
            - policy.rule.delete
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Unknown
 

```
