---
title: "AWS ElastiCache Security Group Created"
aliases:
  - "/rule/4ae68615-866f-4304-b24b-ba048dfa5ca7"


tags:
  - attack.persistence
  - attack.t1136
  - attack.t1136.003



status: experimental





date: Sat, 24 Jul 2021 09:16:11 -0500


---

Detects when an ElastiCache security group has been created.

<!--more-->


## Known false-positives

* A ElastiCache security group may be created by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Security group creations from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://github.com/elastic/detection-rules/blob/598f3d7e0a63221c0703ad9a0ea7e22e7bc5961e/rules/integrations/aws/persistence_elasticache_security_group_creation.toml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_elasticache_security_group_created.yml))
```yaml
title: AWS ElastiCache Security Group Created
id: 4ae68615-866f-4304-b24b-ba048dfa5ca7 
description: Detects when an ElastiCache security group has been created. 
author: Austin Songer @austinsonger
status: experimental
date: 2021/07/24
modified: 2021/08/19
references:
    - https://github.com/elastic/detection-rules/blob/598f3d7e0a63221c0703ad9a0ea7e22e7bc5961e/rules/integrations/aws/persistence_elasticache_security_group_creation.toml
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: elasticache.amazonaws.com
        eventName: 'CreateCacheSecurityGroup'
    condition: selection
level: low
tags:
    - attack.persistence
    - attack.t1136
    - attack.t1136.003
falsepositives:
- A ElastiCache security group may be created by a system or network administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. Security group creations from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



```
