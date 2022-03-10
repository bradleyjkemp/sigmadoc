---
title: "AWS RDS Master Password Change"
aliases:
  - "/rule/8a63cdd4-6207-414a-85bc-7e032bd3c1a2"


tags:
  - attack.exfiltration
  - attack.t1020



status: experimental





date: Wed, 12 Feb 2020 22:21:52 +0200


---

Detects the change of database master password. It may be a part of data exfiltration.

<!--more-->


## Known false-positives

* Benign changes to a db instance



## References

* https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/rds__explore_snapshots/main.py


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_rds_change_master_password.yml))
```yaml
title: AWS RDS Master Password Change
id: 8a63cdd4-6207-414a-85bc-7e032bd3c1a2
status: experimental
description: Detects the change of database master password. It may be a part of data exfiltration.
author: faloker
date: 2020/02/12
modified: 2021/08/20
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/rds__explore_snapshots/main.py
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: rds.amazonaws.com
        responseElements.pendingModifiedValues.masterUserPassword: '*'
        eventName: ModifyDBInstance
    condition: selection_source
falsepositives:
    - Benign changes to a db instance
level: medium
tags:
    - attack.exfiltration
    - attack.t1020

```