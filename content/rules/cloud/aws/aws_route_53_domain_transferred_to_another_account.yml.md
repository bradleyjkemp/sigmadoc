---
title: "AWS Route 53 Domain Transferred to Another Account"
aliases:
  - "/rule/b056de1a-6e6e-4e40-a67e-97c9808cf41b"


tags:
  - attack.persistence
  - attack.credential_access
  - attack.t1098



status: experimental





date: Thu, 22 Jul 2021 21:41:59 -0500


---

Detects when a request has been made to transfer a Route 53 domain to another AWS account.

<!--more-->


## Known false-positives

* A domain may be transferred to another AWS account by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Domain transfers from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_route_53_domain_transferred_to_another_account.toml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_route_53_domain_transferred_to_another_account.yml))
```yaml
title: AWS Route 53 Domain Transferred to Another Account
id: b056de1a-6e6e-4e40-a67e-97c9808cf41b
description: Detects when a request has been made to transfer a Route 53 domain to another AWS account.
author: Elastic, Austin Songer @austinsonger
status: experimental
date: 2021/07/22
references:
    - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_route_53_domain_transferred_to_another_account.toml
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: route53.amazonaws.com
        eventName: TransferDomainToAnotherAwsAccount
    condition: selection
tags:
    - attack.persistence
    - attack.credential_access
    - attack.t1098
falsepositives:
- A domain may be transferred to another AWS account by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Domain transfers from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
level: low

```