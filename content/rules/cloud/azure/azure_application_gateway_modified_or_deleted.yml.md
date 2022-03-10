---
title: "Azure Application Gateway Modified or Deleted"
aliases:
  - "/rule/ad87d14e-7599-4633-ba81-aeb60cfe8cd6"


tags:
  - attack.impact



status: experimental





date: Mon, 16 Aug 2021 23:30:30 -0500


---

Identifies when a application gateway is modified or deleted.

<!--more-->


## Known false-positives

* Application gateway being modified or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Application gateway modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_application_gateway_modified_or_deleted.yml))
```yaml
title: Azure Application Gateway Modified or Deleted
id: ad87d14e-7599-4633-ba81-aeb60cfe8cd6
description: Identifies when a application gateway is modified or deleted.
author: Austin Songer
status: experimental
date: 2021/08/16
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message: 
            - MICROSOFT.NETWORK/APPLICATIONGATEWAYS/WRITE
            - MICROSOFT.NETWORK/APPLICATIONGATEWAYS/DELETE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Application gateway being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Application gateway modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
