---
title: "Azure Kubernetes Sensitive Role Access"
aliases:
  - "/rule/818fee0c-e0ec-4e45-824e-83e4817b0887"
ruleid: 818fee0c-e0ec-4e45-824e-83e4817b0887

tags:
  - attack.impact



status: experimental





date: Sun, 8 Aug 2021 00:59:35 -0500


---

Identifies when ClusterRoles/Roles are being modified or deleted.

<!--more-->


## Known false-positives

* ClusterRoles/Roles being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* ClusterRoles/Roles modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
* https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
* https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
* https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1
* https://attack.mitre.org/matrices/enterprise/cloud/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_kubernetes_role_access.yml))
```yaml
title: Azure Kubernetes Sensitive Role Access
id: 818fee0c-e0ec-4e45-824e-83e4817b0887
description: Identifies when ClusterRoles/Roles are being modified or deleted.
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
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLES/WRITE
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLES/DELETE
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLES/BIND/ACTION
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLES/ESCALATE/ACTION
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLES/WRITE
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLES/DELETE
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLES/BIND/ACTION
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLES/ESCALATE/ACTION
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - ClusterRoles/Roles being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
 - ClusterRoles/Roles modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```