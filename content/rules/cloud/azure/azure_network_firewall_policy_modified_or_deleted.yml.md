---
title: "Azure Network Firewall Policy Modified or Deleted"
aliases:
  - "/rule/83c17918-746e-4bd9-920b-8e098bf88c23"
ruleid: 83c17918-746e-4bd9-920b-8e098bf88c23

tags:
  - attack.impact



status: experimental





date: Thu, 2 Sep 2021 20:31:27 -0500


---

Identifies when a Firewall Policy is Modified or Deleted.

<!--more-->


## Known false-positives

* Firewall Policy being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Firewall Policy modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_network_firewall_policy_modified_or_deleted.yml))
```yaml
title: Azure Network Firewall Policy Modified or Deleted
id: 83c17918-746e-4bd9-920b-8e098bf88c23
description: Identifies when a Firewall Policy is Modified or Deleted.
author: Austin Songer @austinsonger
status: experimental
date: 2021/09/02
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message: 
            - MICROSOFT.NETWORK/FIREWALLPOLICIES/WRITE
            - MICROSOFT.NETWORK/FIREWALLPOLICIES/JOIN/ACTION
            - MICROSOFT.NETWORK/FIREWALLPOLICIES/CERTIFICATES/ACTION
            - MICROSOFT.NETWORK/FIREWALLPOLICIES/DELETE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Firewall Policy being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Firewall Policy modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
