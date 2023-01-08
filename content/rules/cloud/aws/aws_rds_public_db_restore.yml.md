---
title: "Restore Public AWS RDS Instance"
aliases:
  - "/rule/c3f265c7-ff03-4056-8ab2-d486227b4599"
ruleid: c3f265c7-ff03-4056-8ab2-d486227b4599

tags:
  - attack.exfiltration
  - attack.t1020



status: experimental





date: Wed, 12 Feb 2020 22:21:52 +0200


---

Detects the recovery of a new public database instance from a snapshot. It may be a part of data exfiltration.

<!--more-->


## Known false-positives

* unknown



## References

* https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/rds__explore_snapshots/main.py


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_rds_public_db_restore.yml))
```yaml
title: Restore Public AWS RDS Instance
id: c3f265c7-ff03-4056-8ab2-d486227b4599
status: experimental
description: Detects the recovery of a new public database instance from a snapshot. It may be a part of data exfiltration.
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
        responseElements.publiclyAccessible: 'true'
        eventName: RestoreDBInstanceFromDBSnapshot
    condition: selection_source
falsepositives:
    - unknown
level: high
tags:
    - attack.exfiltration
    - attack.t1020

```
