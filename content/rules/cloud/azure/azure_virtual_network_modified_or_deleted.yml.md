---
title: "Azure Virtual Network Modified or Deleted"
aliases:
  - "/rule/bcfcc962-0e4a-4fd9-84bb-a833e672df3f"
ruleid: bcfcc962-0e4a-4fd9-84bb-a833e672df3f

tags:
  - attack.impact



status: experimental





date: Sun, 8 Aug 2021 22:16:06 -0500


---

Identifies when a Virtual Network is modified or deleted in Azure.

<!--more-->


## Known false-positives

* Virtual Network being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Virtual Network modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_virtual_network_modified_or_deleted.yml))
```yaml
title: Azure Virtual Network Modified or Deleted
id: bcfcc962-0e4a-4fd9-84bb-a833e672df3f
description: Identifies when a Virtual Network is modified or deleted in Azure.
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
        properties.message|startswith:
            - MICROSOFT.NETWORK/VIRTUALNETWORKGATEWAYS/
            - MICROSOFT.NETWORK/VIRTUALNETWORKS/
        properties.message|endswith:
            - /WRITE
            - /DELETE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Virtual Network being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Virtual Network modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
