---
title: "AWS Route 53 Domain Transfer Lock Disabled"
aliases:
  - "/rule/3940b5f1-3f46-44aa-b746-ebe615b879e0"


tags:
  - attack.persistence
  - attack.credential_access
  - attack.t1098



status: experimental





date: Thu, 22 Jul 2021 21:46:13 -0500


---

Detects when a transfer lock was removed from a Route 53 domain. It is recommended to refrain from performing this action unless intending to transfer the domain to a different registrar.

<!--more-->


## Known false-positives

* A domain transfer lock may be disabled by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Activity from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_route_53_domain_transfer_lock_disabled.toml
* https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html
* https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_route_53_domain_transferred_lock_disabled.yml))
```yaml
title: AWS Route 53 Domain Transfer Lock Disabled
id: 3940b5f1-3f46-44aa-b746-ebe615b879e0
description: Detects when a transfer lock was removed from a Route 53 domain. It is recommended to refrain from performing this action unless intending to transfer the domain to a different registrar. 
author: Elastic, Austin Songer @austinsonger
status: experimental
date: 2021/07/22
references:
    - https://github.com/elastic/detection-rules/blob/main/rules/integrations/aws/persistence_route_53_domain_transfer_lock_disabled.toml
    - https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html
    - https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_DisableDomainTransferLock.html
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: route53.amazonaws.com
        eventName: DisableDomainTransferLock
    condition: selection
level: low
tags:
    - attack.persistence
    - attack.credential_access
    - attack.t1098
falsepositives:
- A domain transfer lock may be disabled by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Activity from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.


```
