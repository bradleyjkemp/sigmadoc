---
title: "AWS EKS Cluster Created or Deleted"
aliases:
  - "/rule/33d50d03-20ec-4b74-a74e-1e65a38af1c0"
ruleid: 33d50d03-20ec-4b74-a74e-1e65a38af1c0

tags:
  - attack.impact
  - attack.t1485



status: experimental





date: Mon, 16 Aug 2021 09:58:48 -0500


---

Identifies when an EKS cluster is created or deleted.

<!--more-->


## Known false-positives

* EKS Cluster being created or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* EKS Cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://any-api.com/amazonaws_com/eks/docs/API_Description


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/aws/aws_eks_cluster_created_or_deleted.yml))
```yaml
title: AWS EKS Cluster Created or Deleted
id: 33d50d03-20ec-4b74-a74e-1e65a38af1c0
description: Identifies when an EKS cluster is created or deleted.
author: Austin Songer
status: experimental
date: 2021/08/16
references:
    - https://any-api.com/amazonaws_com/eks/docs/API_Description
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventSource: eks.amazonaws.com
        eventName: 
            - CreateCluster
            - DeleteCluster
    condition: selection
level: low
tags:
    - attack.impact
    - attack.t1485
falsepositives:
 - EKS Cluster being created or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - EKS Cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
