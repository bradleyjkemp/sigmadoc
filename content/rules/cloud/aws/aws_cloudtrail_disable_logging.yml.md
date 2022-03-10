---
title: "AWS CloudTrail Important Change"
aliases:
  - "/rule/4db60cc0-36fb-42b7-9b58-a5b53019fb74"


tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Tue, 21 Jan 2020 15:06:44 +0200


---

Detects disabling, deleting and updating of a Trail

<!--more-->


## Known false-positives

* Valid change in a Trail



## References

* https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_cloudtrail_disable_logging.yml))
```yaml
title: AWS CloudTrail Important Change
id: 4db60cc0-36fb-42b7-9b58-a5b53019fb74
status: experimental
description: Detects disabling, deleting and updating of a Trail
author: vitaliy0x1
date: 2020/01/21
modified: 2021/08/09
references:
    - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/best-practices-security.html
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: cloudtrail.amazonaws.com
        eventName:
            - StopLogging
            - UpdateTrail
            - DeleteTrail
    condition: selection_source
falsepositives:
    - Valid change in a Trail
level: medium
tags:
    - attack.defense_evasion
    - attack.t1562.001

```