---
title: "Number Of Resource Creation Or Deployment Activities"
aliases:
  - "/rule/d2d901db-7a75-45a1-bc39-0cbf00812192"


tags:
  - attack.t1098



status: test





date: Sun, 15 Aug 2021 16:00:14 +0200


---

Number of VM creations or deployment activities occur in Azure via the AzureActivity log.

<!--more-->


## Known false-positives

* Valid change



## References

* https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AzureActivity/Creating_Anomalous_Number_Of_Resources_detection.yaml


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_creating_number_of_resources_detection.yml))
```yaml
title: Number Of Resource Creation Or Deployment Activities
id: d2d901db-7a75-45a1-bc39-0cbf00812192
status: test
description: Number of VM creations or deployment activities occur in Azure via the AzureActivity log.
author: sawwinnnaung
references:
  - https://github.com/Azure/Azure-Sentinel/blob/master/Detections/AzureActivity/Creating_Anomalous_Number_Of_Resources_detection.yaml
date: 2020/05/07
modified: 2021/11/27
logsource:
  product: azure
  service: AzureActivity
detection:
  keywords:
    - Microsoft.Compute/virtualMachines/write
    - Microsoft.Resources/deployments/write
  condition: keywords
falsepositives:
  - Valid change
level: medium
tags:
  - attack.t1098

```
