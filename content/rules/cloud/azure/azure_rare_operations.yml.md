---
title: "Rare Subscription-level Operations In Azure"
aliases:
  - "/rule/c1182e02-49a3-481c-b3de-0fadc4091488"
ruleid: c1182e02-49a3-481c-b3de-0fadc4091488

tags:
  - attack.t1003



status: test





date: Sun, 15 Aug 2021 16:00:14 +0200


---

Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.

<!--more-->


## Known false-positives

* Valid change



## References

* https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AzureActivity/RareOperations.yaml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_rare_operations.yml))
```yaml
title: Rare Subscription-level Operations In Azure
id: c1182e02-49a3-481c-b3de-0fadc4091488
status: test
description: Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.
author: sawwinnnaung
references:
  - https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AzureActivity/RareOperations.yaml
date: 2020/05/07
modified: 2021/11/27
logsource:
  product: azure
  service: AzureActivity
detection:
  keywords:
    - Microsoft.DocumentDB/databaseAccounts/listKeys/action
    - Microsoft.Maps/accounts/listKeys/action
    - Microsoft.Media/mediaservices/listKeys/action
    - Microsoft.CognitiveServices/accounts/listKeys/action
    - Microsoft.Storage/storageAccounts/listKeys/action
    - Microsoft.Compute/snapshots/write
    - Microsoft.Network/networkSecurityGroups/write
  condition: keywords
falsepositives:
  - Valid change
level: medium
tags:
  - attack.t1003

```
