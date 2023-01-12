---
title: "AWS EC2 Disable EBS Encryption"
aliases:
  - "/rule/16124c2d-e40b-4fcc-8f2c-5ab7870a2223"
ruleid: 16124c2d-e40b-4fcc-8f2c-5ab7870a2223

tags:
  - attack.impact
  - attack.t1486
  - attack.t1565



status: stable





date: Tue, 29 Jun 2021 11:06:00 +0700


---

Identifies disabling of default Amazon Elastic Block Store (EBS) encryption in the current region. Disabling default encryption does not change the encryption status of your existing volumes.

<!--more-->


## Known false-positives

* System Administrator Activities
* DEV, UAT, SAT environment. You should apply this rule with PROD account only.



## References

* https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_ec2_disable_encryption.yml))
```yaml
title: AWS EC2 Disable EBS Encryption
id: 16124c2d-e40b-4fcc-8f2c-5ab7870a2223
status: stable
description: Identifies disabling of default Amazon Elastic Block Store (EBS) encryption in the current region. Disabling default encryption does not change the encryption status of your existing volumes.
author: Sittikorn S
date: 2021/06/29
modified: 2021/08/20
references:
    - https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html
tags:
    - attack.impact
    - attack.t1486
    - attack.t1565
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: ec2.amazonaws.com
        eventName: DisableEbsEncryptionByDefault
    condition: selection
falsepositives:
    - System Administrator Activities
    - DEV, UAT, SAT environment. You should apply this rule with PROD account only.
level: medium

```