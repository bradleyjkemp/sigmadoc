---
title: "Azure Kubernetes RoleBinding/ClusterRoleBinding Modified and Deleted"
aliases:
  - "/rule/25cb259b-bbdc-4b87-98b7-90d7c72f8743"
ruleid: 25cb259b-bbdc-4b87-98b7-90d7c72f8743

tags:
  - attack.impact
  - attack.credential_access



status: experimental





date: Sat, 7 Aug 2021 13:05:19 -0500


---

Detects the creation or patching of potential malicious RoleBinding/ClusterRoleBinding.

<!--more-->


## Known false-positives

* RoleBinding/ClusterRoleBinding being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* RoleBinding/ClusterRoleBinding modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
* https://www.microsoft.com/security/blog/2021/03/23/secure-containerized-environments-with-updated-threat-matrix-for-kubernetes/
* https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/
* https://medium.com/mitre-engenuity/att-ck-for-containers-now-available-4c2359654bf1
* https://attack.mitre.org/matrices/enterprise/cloud/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_kubernetes_rolebinding_modified_or_deleted.yml))
```yaml
title: Azure Kubernetes RoleBinding/ClusterRoleBinding Modified and Deleted
id: 25cb259b-bbdc-4b87-98b7-90d7c72f8743
description: Detects the creation or patching of potential malicious RoleBinding/ClusterRoleBinding.
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
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/WRITE 
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/CLUSTERROLEBINDINGS/DELETE
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/WRITE
            - MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/RBAC.AUTHORIZATION.K8S.IO/ROLEBINDINGS/DELETE
    condition: selection
level: medium
tags:
    - attack.impact
    - attack.credential_access
falsepositives:
 - RoleBinding/ClusterRoleBinding being modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - RoleBinding/ClusterRoleBinding modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.
 

```
