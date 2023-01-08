---
title: "Azure Firewall Modified or Deleted"
aliases:
  - "/rule/512cf937-ea9b-4332-939c-4c2c94baadcd"
ruleid: 512cf937-ea9b-4332-939c-4c2c94baadcd

tags:
  - attack.impact



status: experimental





date: Sun, 8 Aug 2021 22:42:51 -0500


---

Identifies when a firewall is created, modified, or deleted.

<!--more-->


## Known false-positives

* Firewall being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Firewall modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_firewall_modified_or_deleted.yml))
```yaml
title: Azure Firewall Modified or Deleted
id: 512cf937-ea9b-4332-939c-4c2c94baadcd
description: Identifies when a firewall is created, modified, or deleted.
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/08
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message: 
            - MICROSOFT.NETWORK/AZUREFIREWALLS/WRITE
            - MICROSOFT.NETWORK/AZUREFIREWALLS/DELETE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Firewall being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Firewall modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
