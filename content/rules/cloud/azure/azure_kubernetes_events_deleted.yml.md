---
title: "Azure Kubernetes Events Deleted"
aliases:
  - "/rule/225d8b09-e714-479c-a0e4-55e6f29adf35"
ruleid: 225d8b09-e714-479c-a0e4-55e6f29adf35

tags:
  - attack.defense_evasion
  - attack.t1562
  - attack.t1562.001



status: experimental





date: Sat, 24 Jul 2021 10:20:11 -0500


---

Detects when Events are deleted in Azure Kubernetes. An adversary may delete events in Azure Kubernetes in an attempt to evade detection.

<!--more-->


## Known false-positives

* Event deletions may be done by a system or network administrator. Verify whether the username, hostname, and/or resource name should be making changes in your environment. Events deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
* https://github.com/elastic/detection-rules/blob/da3852b681cf1a33898b1535892eab1f3a76177a/rules/integrations/azure/defense_evasion_kubernetes_events_deleted.toml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_kubernetes_events_deleted.yml))
```yaml
title: Azure Kubernetes Events Deleted
id: 225d8b09-e714-479c-a0e4-55e6f29adf35
description: Detects when Events are deleted in Azure Kubernetes. An adversary may delete events in Azure Kubernetes in an attempt to evade detection.
author: Austin Songer @austinsonger
status: experimental
date: 2021/07/24
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
    - https://github.com/elastic/detection-rules/blob/da3852b681cf1a33898b1535892eab1f3a76177a/rules/integrations/azure/defense_evasion_kubernetes_events_deleted.toml
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection_operation_name:
          properties.message: MICROSOFT.KUBERNETES/CONNECTEDCLUSTERS/EVENTS.K8S.IO/EVENTS/DELETE
    condition: selection_operation_name
level: medium
tags:
    - attack.defense_evasion
    - attack.t1562
    - attack.t1562.001
falsepositives:
- Event deletions may be done by a system or network administrator. Verify whether the username, hostname, and/or resource name should be making changes in your environment. Events deletions from unfamiliar users or hosts should be investigated. If known behavior is causing false positives, it can be exempted from the rule.


```
