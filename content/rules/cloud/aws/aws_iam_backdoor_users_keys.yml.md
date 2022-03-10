---
title: "AWS IAM Backdoor Users Keys"
aliases:
  - "/rule/0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2"


tags:
  - attack.persistence
  - attack.t1098



status: experimental





date: Wed, 12 Feb 2020 22:22:38 +0200


---

Detects AWS API key creation for a user by another user. Backdoored users can be used to obtain persistence in the AWS environment. Also with this alert, you can detect a flow of AWS keys in your org.

<!--more-->


## Known false-positives

* Adding user keys to their own accounts (the filter cannot cover all possible variants of user naming)
* AWS API keys legitimate exchange workflows



## References

* https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/iam__backdoor_users_keys/main.py


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_iam_backdoor_users_keys.yml))
```yaml
title: AWS IAM Backdoor Users Keys
id: 0a5177f4-6ca9-44c2-aacf-d3f3d8b6e4d2
status: experimental
description: Detects AWS API key creation for a user by another user. Backdoored users can be used to obtain persistence in the AWS environment. Also with this alert, you can detect a flow of AWS keys in your org.
author: faloker
date: 2020/02/12
modified: 2021/08/20
references:
    - https://github.com/RhinoSecurityLabs/pacu/blob/master/pacu/modules/iam__backdoor_users_keys/main.py
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: iam.amazonaws.com
        eventName: CreateAccessKey
    filter:
        userIdentity.arn|contains: responseElements.accessKey.userName
    condition: selection_source and not filter
fields:
    - userIdentity.arn
    - responseElements.accessKey.userName
    - errorCode
    - errorMessage
falsepositives:
    - Adding user keys to their own accounts (the filter cannot cover all possible variants of user naming)
    - AWS API keys legitimate exchange workflows
level: medium
tags:
    - attack.persistence
    - attack.t1098

```
