---
title: "Azure Kubernetes Cluster Created or Deleted"
aliases:
  - "/rule/9541f321-7cba-4b43-80fc-fbd1fb922808"


tags:
  - attack.impact



status: experimental





date: Sat, 7 Aug 2021 22:18:28 -0500


---

Detects when a Azure Kubernetes Cluster is created or deleted.

<!--more-->


## Known false-positives

* Kubernetes cluster being created or  deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Kubernetes cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
* https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
* https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
* https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1
* https://attack.mitre.org/matrices/enterprise/cloud/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_kubernetes_cluster_created_or_deleted.yml))
```yaml
title: Azure Kubernetes Cluster Created or Deleted
id: 9541f321-7cba-4b43-80fc-fbd1fb922808
description: Detects when a Azure Kubernetes Cluster is created or deleted.
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/07
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
    - https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
    - https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
    - https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1
    - https://attack.mitre.org/matrices/enterprise/cloud/
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message: 
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/WRITE
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/DELETE
    condition: selection
level: low
tags:
    - attack.impact
falsepositives:
 - Kubernetes cluster being created or  deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
 - Kubernetes cluster created or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
 

```
