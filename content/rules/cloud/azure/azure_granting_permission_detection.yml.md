---
title: "Granting Of Permissions To An Account"
aliases:
  - "/rule/a622fcd2-4b5a-436a-b8a2-a4171161833c"
ruleid: a622fcd2-4b5a-436a-b8a2-a4171161833c

tags:
  - attack.t1098



status: test





date: Sun, 15 Aug 2021 16:00:14 +0200


---

Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.

<!--more-->


## Known false-positives

* Valid change



## References

* https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AzureActivity/Granting_Permissions_To_Account_detection.yaml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_granting_permission_detection.yml))
```yaml
title: Granting Of Permissions To An Account
id: a622fcd2-4b5a-436a-b8a2-a4171161833c
status: test
description: Identifies IPs from which users grant access to other users on azure resources and alerts when a previously unseen source IP address is used.
author: sawwinnnaung
references:
  - https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AzureActivity/Granting_Permissions_To_Account_detection.yaml
date: 2020/05/07
modified: 2021/11/27
logsource:
  product: azure
  service: AzureActivity
detection:
  keywords:
    - Microsoft.Authorization/roleAssignments/write
  condition: keywords
falsepositives:
  - Valid change
level: medium
tags:
  - attack.t1098

```
