---
title: "AWS User Login Profile Was Modified"
aliases:
  - "/rule/055fb148-60f8-462d-ad16-26926ce050f1"


tags:
  - attack.persistence
  - attack.t1098



status: experimental





date: Sun, 22 Nov 2020 00:33:47 +0800


---

An attacker with the iam:UpdateLoginProfile permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.
With this alert, it is used to detect anyone is changing password on behalf of other users.


<!--more-->


## Known false-positives

* Legit User Account Administration



## References

* https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_update_login_profile.yml))
```yaml
title: AWS User Login Profile Was Modified
id: 055fb148-60f8-462d-ad16-26926ce050f1 
status: experimental
description: | 
 An attacker with the iam:UpdateLoginProfile permission on other users can change the password used to login to the AWS console on any user that already has a login profile setup.
 With this alert, it is used to detect anyone is changing password on behalf of other users.
author: toffeebr33k
date: 2021/08/09
references:
    - https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation
logsource:
    product: aws
    service: cloudtrail
detection:
    selection_source:
        eventSource: iam.amazonaws.com
        eventName: UpdateLoginProfile
    filter:
        userIdentity.arn|contains: requestParameters.userName
    condition: selection_source and not filter
fields:
    - userIdentity.arn
    - requestParameters.userName
    - errorCode
    - errorMessage
falsepositives:
    - Legit User Account Administration 
level: high
tags:
    - attack.persistence
    - attack.t1098

```
