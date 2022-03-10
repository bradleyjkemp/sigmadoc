---
title: "AWS Attached Malicious Lambda Layer"
aliases:
  - "/rule/97fbabf8-8e1b-47a2-b7d5-a418d2b95e3d"


tags:
  - attack.privilege_escalation



status: experimental





date: Thu, 23 Sep 2021 08:38:02 -0500


---

Detects when an user attached a Lambda layer to an existing function to override a library that is in use by the function, where their malicious code could utilize the function's IAM role for AWS API calls. This would give an adversary access to the privileges associated with the Lambda service role that is attached to that function.

<!--more-->


## Known false-positives

* Lambda Layer being attached may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Lambda Layer being attached from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.aws.amazon.com/lambda/latest/dg/API_UpdateFunctionConfiguration.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_attached_malicious_lambda_layer.yml))
```yaml
title: AWS Attached Malicious Lambda Layer
id: 97fbabf8-8e1b-47a2-b7d5-a418d2b95e3d
description: Detects when an user attached a Lambda layer to an existing function to override a library that is in use by the function, where their malicious code could utilize the function's IAM role for AWS API calls. This would give an adversary access to the privileges associated with the Lambda service role that is attached to that function.
author: Austin Songer
status: experimental
date: 2021/09/23
references:
    - https://docs.aws.amazon.com/lambda/latest/dg/API_UpdateFunctionConfiguration.html
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: lambda.amazonaws.com
        eventName|startswith: UpdateFunctionConfiguration
    condition: selection
level: medium
tags:
    - attack.privilege_escalation
falsepositives:
 - Lambda Layer being attached may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Lambda Layer being attached from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
