---
title: "AWS EFS Fileshare Mount Modified or Deleted"
aliases:
  - "/rule/6a7ba45c-63d8-473e-9736-2eaabff79964"


tags:
  - attack.impact
  - attack.t1485



status: experimental





date: Sun, 15 Aug 2021 14:26:48 -0500


---

Detects when a EFS Fileshare Mount is modified or deleted. An adversary breaking any file system using the mount target that is being deleted, which might disrupt instances or applications using those mounts.

<!--more-->


## Known false-positives

* unknown



## References

* https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_efs_fileshare_mount_modified_or_deleted.yml))
```yaml
title: AWS EFS Fileshare Mount Modified or Deleted
id: 6a7ba45c-63d8-473e-9736-2eaabff79964
status: experimental
description: Detects when a EFS Fileshare Mount is modified or deleted. An adversary breaking any file system using the mount target that is being deleted, which might disrupt instances or applications using those mounts.
author: Austin Songer @austinsonger
date: 2021/08/15
references:
    - https://docs.aws.amazon.com/efs/latest/ug/API_DeleteMountTarget.html
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: elasticfilesystem.amazonaws.com
        eventName: DeleteMountTarget
    condition: selection
falsepositives:
    - unknown
level: medium
tags:
    - attack.impact
    - attack.t1485

```
