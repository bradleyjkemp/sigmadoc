---
title: "AWS STS GetSessionToken Misuse"
aliases:
  - "/rule/b45ab1d2-712f-4f01-a751-df3826969807"
ruleid: b45ab1d2-712f-4f01-a751-df3826969807

tags:
  - attack.lateral_movement
  - attack.privilege_escalation
  - attack.t1548
  - attack.t1550
  - attack.t1550.001



status: experimental





date: Sat, 24 Jul 2021 12:05:44 -0500


---

Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.

<!--more-->


## Known false-positives

* GetSessionToken may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. GetSessionToken from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://github.com/elastic/detection-rules/pull/1213
* https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_sts_getsessiontoken_misuse.yml))
```yaml
title: AWS STS GetSessionToken Misuse
id: b45ab1d2-712f-4f01-a751-df3826969807
description: Identifies the suspicious use of GetSessionToken. Tokens could be created and used by attackers to move laterally and escalate privileges.
author: Austin Songer @austinsonger
status: experimental
date: 2021/07/24
references:
    - https://github.com/elastic/detection-rules/pull/1213
    - https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: sts.amazonaws.com
        eventName: GetSessionToken
        userIdentity.type: IAMUser
    condition: selection
level: low
tags:
  - attack.lateral_movement
  - attack.privilege_escalation
  - attack.t1548
  - attack.t1550
  - attack.t1550.001
falsepositives:
- GetSessionToken may be done by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. GetSessionToken from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```