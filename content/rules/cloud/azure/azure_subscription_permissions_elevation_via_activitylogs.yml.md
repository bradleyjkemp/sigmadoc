---
title: "Azure Subscription Permission Elevation Via ActivityLogs"
aliases:
  - "/rule/09438caa-07b1-4870-8405-1dbafe3dad95"
ruleid: 09438caa-07b1-4870-8405-1dbafe3dad95

tags:
  - attack.initial_access
  - attack.t1078



status: experimental





date: Fri, 26 Nov 2021 11:32:57 -0600


---

Detects when a user has been elevated to manage all Azure Subscriptions. This change should be investigated immediately if it isn't planned. This setting could allow an attacker access to Azure subscriptions in your environment.

<!--more-->


## Known false-positives

* If this was approved by System Administrator.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftauthorization


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_subscription_permissions_elevation_via_activitylogs.yml))
```yaml
title: Azure Subscription Permission Elevation Via ActivityLogs
id: 09438caa-07b1-4870-8405-1dbafe3dad95
status: experimental
author: Austin Songer @austinsonger
date: 2021/11/26
description: Detects when a user has been elevated to manage all Azure Subscriptions. This change should be investigated immediately if it isn't planned. This setting could allow an attacker access to Azure subscriptions in your environment.
references:
  - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftauthorization
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection1:
        properties.message: 
            - MICROSOFT.AUTHORIZATION/ELEVATEACCESS/ACTION
    condition: selection1
level: high
falsepositives:
  - If this was approved by System Administrator.
tags:
  - attack.initial_access
  - attack.t1078

```
