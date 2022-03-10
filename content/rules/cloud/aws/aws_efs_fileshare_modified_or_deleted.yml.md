---
title: "AWS EFS Fileshare Modified or Deleted"
aliases:
  - "/rule/25cb1ba1-8a19-4a23-a198-d252664c8cef"


tags:
  - attack.impact



status: experimental





date: Sun, 15 Aug 2021 14:27:22 -0500


---

Detects when a EFS Fileshare is modified or deleted. You can't delete a file system that is in use. If the file system has any mount targets, the adversary must first delete them, so deletion of a mount will occur before deletion of a fileshare.

<!--more-->


## Known false-positives

* unknown



## References

* https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_efs_fileshare_modified_or_deleted.yml))
```yaml
title: AWS EFS Fileshare Modified or Deleted
id: 25cb1ba1-8a19-4a23-a198-d252664c8cef
status: experimental
description: Detects when a EFS Fileshare is modified or deleted. You can't delete a file system that is in use. If the file system has any mount targets, the adversary must first delete them, so deletion of a mount will occur before deletion of a fileshare.
author: Austin Songer @austinsonger
date: 2021/08/15
references:
    - https://docs.aws.amazon.com/efs/latest/ug/API_DeleteFileSystem.html
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: elasticfilesystem.amazonaws.com
        eventName: DeleteFileSystem
    condition: selection
falsepositives:
    - unknown
level: medium
tags:
    - attack.impact

```