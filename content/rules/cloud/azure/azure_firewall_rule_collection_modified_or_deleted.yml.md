---
title: "Azure Firewall Rule Collection Modified or Deleted"
aliases:
  - "/rule/025c9fe7-db72-49f9-af0d-31341dd7dd57"
ruleid: 025c9fe7-db72-49f9-af0d-31341dd7dd57

tags:
  - attack.impact



status: experimental





date: Sun, 8 Aug 2021 22:43:47 -0500


---

Identifies when Rule Collections (Application, NAT, and Network) is being modified or deleted.

<!--more-->


## Known false-positives

* Rule Collections (Application, NAT, and Network) being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Rule Collections (Application, NAT, and Network) modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_firewall_rule_collection_modified_or_deleted.yml))
```yaml
title: Azure Firewall Rule Collection Modified or Deleted
id: 025c9fe7-db72-49f9-af0d-31341dd7dd57
description: Identifies when Rule Collections (Application, NAT, and Network) is being modified or deleted.
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
            - MICROSOFT.NETWORK/AZUREFIREWALLS/APPLICATIONRULECOLLECTIONS/WRITE
            - MICROSOFT.NETWORK/AZUREFIREWALLS/APPLICATIONRULECOLLECTIONS/DELETE
            - MICROSOFT.NETWORK/AZUREFIREWALLS/NATRULECOLLECTIONS/WRITE
            - MICROSOFT.NETWORK/AZUREFIREWALLS/NATRULECOLLECTIONS/DELETE
            - MICROSOFT.NETWORK/AZUREFIREWALLS/NETWORKRULECOLLECTIONS/WRITE
            - MICROSOFT.NETWORK/AZUREFIREWALLS/NETWORKRULECOLLECTIONS/DELETE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Rule Collections (Application, NAT, and Network) being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Rule Collections (Application, NAT, and Network) modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
