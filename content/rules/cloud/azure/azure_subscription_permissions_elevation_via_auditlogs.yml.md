---
title: "Azure Subscription Permission Elevation Via AuditLogs"
aliases:
  - "/rule/ca9bf243-465e-494a-9e54-bf9fc239057d"


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

* https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts#assignment-and-elevation


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_subscription_permissions_elevation_via_auditlogs.yml))
```yaml
title: Azure Subscription Permission Elevation Via AuditLogs
id: ca9bf243-465e-494a-9e54-bf9fc239057d
status: experimental
author: Austin Songer @austinsonger
date: 2021/11/26
description: Detects when a user has been elevated to manage all Azure Subscriptions. This change should be investigated immediately if it isn't planned. This setting could allow an attacker access to Azure subscriptions in your environment.
references:
  - https://docs.microsoft.com/en-us/azure/active-directory/fundamentals/security-operations-privileged-accounts#assignment-and-elevation
logsource:
  product: azure
  service: azure.auditlogs
detection:
  selection:
    Category: 'Administrative'
    OperationName: 'Assigns the caller to user access admin'
  condition: selection
level: high
falsepositives:
  - If this was approved by System Administrator.
tags:
  - attack.initial_access
  - attack.t1078

```
