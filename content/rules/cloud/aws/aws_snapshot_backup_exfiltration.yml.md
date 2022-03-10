---
title: "AWS Snapshot Backup Exfiltration"
aliases:
  - "/rule/abae8fec-57bd-4f87-aff6-6e3db989843d"


tags:
  - attack.exfiltration
  - attack.t1537



status: test





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the modification of an EC2 snapshot's permissions to enable access from another account

<!--more-->


## Known false-positives

* Valid change to a snapshot's permissions



## References

* https://www.justice.gov/file/1080281/download
* https://attack.mitre.org/techniques/T1537/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_snapshot_backup_exfiltration.yml))
```yaml
title: AWS Snapshot Backup Exfiltration
id: abae8fec-57bd-4f87-aff6-6e3db989843d
status: test
description: Detects the modification of an EC2 snapshot's permissions to enable access from another account
author: Darin Smith
date: 2021/05/17
modified: 2021/08/19
references:
  - https://www.justice.gov/file/1080281/download
  - https://attack.mitre.org/techniques/T1537/
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_source:
    eventSource: ec2.amazonaws.com
    eventName: ModifySnapshotAttribute
  condition: selection_source
falsepositives:
  - Valid change to a snapshot's permissions
level: medium
tags:
  - attack.exfiltration
  - attack.t1537

```
