---
title: "Google Cloud Kubernetes RoleBinding"
aliases:
  - "/rule/0322d9f2-289a-47c2-b5e1-b63c90901a3e"
ruleid: 0322d9f2-289a-47c2-b5e1-b63c90901a3e

tags:
  - attack.credential_access



status: experimental





date: Mon, 9 Aug 2021 22:01:16 -0500


---

Detects the creation or patching of potential malicious RoleBinding. This includes RoleBindings and ClusterRoleBinding.

<!--more-->


## Known false-positives

* RoleBindings and ClusterRoleBinding being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* RoleBindings and ClusterRoleBinding modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://github.com/elastic/detection-rules/pull/1267
* https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/cluster-role-v1/#ClusterRole
* https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control
* https://kubernetes.io/docs/reference/access-authn-authz/rbac/
* https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gcp/gcp_kubernetes_rolebinding.yml))
```yaml
title: Google Cloud Kubernetes RoleBinding
id: 0322d9f2-289a-47c2-b5e1-b63c90901a3e
description: Detects the creation or patching of potential malicious RoleBinding. This includes RoleBindings and ClusterRoleBinding.
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/09
references:
    - https://github.com/elastic/detection-rules/pull/1267
    - https://kubernetes.io/docs/reference/kubernetes-api/authorization-resources/cluster-role-v1/#ClusterRole
    - https://cloud.google.com/kubernetes-engine/docs/how-to/role-based-access-control
    - https://kubernetes.io/docs/reference/access-authn-authz/rbac/
    - https://cloud.google.com/kubernetes-engine/docs/how-to/audit-logging
logsource:
  product: gcp
  service: gcp.audit
detection:
    selection:
        gcp.audit.method_name: 
            - io.k8s.authorization.rbac.v*.clusterrolebindings.create
            - io.k8s.authorization.rbac.v*.rolebindings.create
            - io.k8s.authorization.rbac.v*.clusterrolebindings.patch
            - io.k8s.authorization.rbac.v*.rolebindings.patch
            - io.k8s.authorization.rbac.v*.clusterrolebindings.update
            - io.k8s.authorization.rbac.v*.rolebindings.update
            - io.k8s.authorization.rbac.v*.clusterrolebindings.delete
            - io.k8s.authorization.rbac.v*.rolebindings.delete
    condition: selection
level: medium
tags:
    - attack.credential_access
falsepositives:
 - RoleBindings and ClusterRoleBinding being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - RoleBindings and ClusterRoleBinding modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```