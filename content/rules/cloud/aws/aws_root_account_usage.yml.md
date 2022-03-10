---
title: "AWS Root Credentials"
aliases:
  - "/rule/8ad1600d-e9dc-4251-b0ee-a65268f29add"


tags:
  - attack.privilege_escalation
  - attack.t1078.004



status: experimental





date: Tue, 21 Jan 2020 15:07:32 +0200


---

Detects AWS root account usage

<!--more-->


## Known false-positives

* AWS Tasks That Require AWS Account Root User Credentials https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html



## References

* https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_root_account_usage.yml))
```yaml
title: AWS Root Credentials
id: 8ad1600d-e9dc-4251-b0ee-a65268f29add
status: experimental
description: Detects AWS root account usage
author: vitaliy0x1
date: 2020/01/21
modified: 2021/08/09
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
logsource:
  product: aws
  service: cloudtrail
detection:
  selection_usertype:
    userIdentity.type: Root
  selection_eventtype:
    eventType: AwsServiceEvent
  condition: selection_usertype and not selection_eventtype
falsepositives:
  - AWS Tasks That Require AWS Account Root User Credentials https://docs.aws.amazon.com/general/latest/gr/aws_tasks-that-require-root.html
level: medium
tags:
  - attack.privilege_escalation
  - attack.t1078.004

```
