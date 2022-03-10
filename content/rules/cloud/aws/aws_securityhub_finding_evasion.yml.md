---
title: "AWS SecurityHub Findings Evasion"
aliases:
  - "/rule/a607e1fe-74bf-4440-a3ec-b059b9103157"


tags:
  - attack.defense_evasion
  - attack.t1562



status: stable





date: Mon, 28 Jun 2021 15:42:34 +0700


---

Detects the modification of the findings on SecurityHub.

<!--more-->


## Known false-positives

* System or Network administrator behaviors
* DEV, UAT, SAT environment. You should apply this rule with PROD environment only.



## References

* https://docs.aws.amazon.com/cli/latest/reference/securityhub/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_securityhub_finding_evasion.yml))
```yaml
title: AWS SecurityHub Findings Evasion
id: a607e1fe-74bf-4440-a3ec-b059b9103157
status: stable
description: Detects the modification of the findings on SecurityHub.
author: Sittikorn S
date: 2021/06/28
references:
    - https://docs.aws.amazon.com/cli/latest/reference/securityhub/
tags:
    - attack.defense_evasion
    - attack.t1562
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: securityhub.amazonaws.com
        eventName:
          - 'BatchUpdateFindings'
          - 'DeleteInsight'
          - 'UpdateFindings'
          - 'UpdateInsight'
    condition: selection
fields:
    - sourceIPAddress
    - userIdentity.arn
falsepositives:
    - System or Network administrator behaviors
    - DEV, UAT, SAT environment. You should apply this rule with PROD environment only.
level: high

```
