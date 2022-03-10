---
title: "Azure Kubernetes Pods Deleted"
aliases:
  - "/rule/b02f9591-12c3-4965-986a-88028629b2e1"


tags:
  - attack.impact



status: experimental





date: Sat, 24 Jul 2021 10:24:29 -0500


---

Identifies the deletion of Azure Kubernetes Pods.

<!--more-->


## Known false-positives

* Pods may be deleted by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Pods deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
* https://github.com/elastic/detection-rules/blob/065bf48a9987cd8bd826c098a30ce36e6868ee46/rules/integrations/azure/impact_kubernetes_pod_deleted.toml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_kubernetes_pods_deleted.yml))
```yaml
title: Azure Kubernetes Pods Deleted
id: b02f9591-12c3-4965-986a-88028629b2e1
description: Identifies the deletion of Azure Kubernetes Pods.
author: Austin Songer @austinsonger
status: experimental
date: 2021/07/24
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
    - https://github.com/elastic/detection-rules/blob/065bf48a9987cd8bd826c098a30ce36e6868ee46/rules/integrations/azure/impact_kubernetes_pod_deleted.toml
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection_operation_name:
          properties.message: MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/PODS/DELETE
    condition: selection_operation_name
level: medium
tags:
    - attack.impact
falsepositives:
- Pods may be deleted by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
- Pods deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
