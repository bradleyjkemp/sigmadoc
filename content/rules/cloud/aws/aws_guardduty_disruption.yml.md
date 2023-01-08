---
title: "AWS GuardDuty Important Change"
aliases:
  - "/rule/6e61ee20-ce00-4f8d-8aee-bedd8216f7e3"
ruleid: 6e61ee20-ce00-4f8d-8aee-bedd8216f7e3

tags:
  - attack.defense_evasion
  - attack.t1562.001



status: experimental





date: Tue, 11 Feb 2020 23:28:23 +0200


---

Detects updates of the GuardDuty list of trusted IPs, perhaps to disable security alerts against malicious IPs.

<!--more-->


## Known false-positives

* Valid change in the GuardDuty (e.g. to ignore internal scanners)



## References

* https://github.com/RhinoSecurityLabs/pacu/blob/master/modules/guardduty__whitelist_ip/main.py#L9


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_guardduty_disruption.yml))
```yaml
title: AWS GuardDuty Important Change
id: 6e61ee20-ce00-4f8d-8aee-bedd8216f7e3
status: experimental
description: Detects updates of the GuardDuty list of trusted IPs, perhaps to disable security alerts against malicious IPs.
author: faloker
date: 2020/02/11
modified: 2021/08/09
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/master/modules/guardduty__whitelist_ip/main.py#L9
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: guardduty.amazonaws.com
        eventName: CreateIPSet
    condition: selection_source
falsepositives:
    - Valid change in the GuardDuty (e.g. to ignore internal scanners)
level: high
tags:
    - attack.defense_evasion
    - attack.t1562.001

```
