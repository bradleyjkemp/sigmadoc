---
title: "AWS Suspicious SAML Activity"
aliases:
  - "/rule/f43f5d2f-3f2a-4cc8-b1af-81fde7dbaf0e"


tags:
  - attack.initial_access
  - attack.t1078
  - attack.lateral_movement
  - attack.t1548
  - attack.privilege_escalation
  - attack.t1550
  - attack.t1550.001



status: experimental





date: Wed, 22 Sep 2021 20:15:36 -0500


---

Identifies when suspicious SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML.

<!--more-->


## Known false-positives

* Automated processes that uses Terraform may lead to false positives.
* SAML Provider could be updated by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* SAML Provider being updated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html
* https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_suspicious_saml_activity.yml))
```yaml
title: AWS Suspicious SAML Activity 
id: f43f5d2f-3f2a-4cc8-b1af-81fde7dbaf0e
description: Identifies when suspicious SAML activity has occurred in AWS. An adversary could gain backdoor access via SAML.
author: Austin Songer
status: experimental
date: 2021/09/22
references:
    - https://docs.aws.amazon.com/IAM/latest/APIReference/API_UpdateSAMLProvider.html
    - https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
logsource:
    product: aws
    service: cloudtrail
detection:
    selection1:
        eventSource: sts.amazonaws.com
        eventName: AssumeRoleWithSAML
    selection2:
        eventSource: iam.amazonaws.com
        eventName: UpdateSAMLProvider
    condition: selection1 or selection2
level: medium
tags:
    - attack.initial_access
    - attack.t1078
    - attack.lateral_movement
    - attack.t1548
    - attack.privilege_escalation
    - attack.t1550
    - attack.t1550.001
falsepositives:
 - Automated processes that uses Terraform may lead to false positives.
 - SAML Provider could be updated by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - SAML Provider being updated from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
