---
title: "Azure New CloudShell Created"
aliases:
  - "/rule/72af37e2-ec32-47dc-992b-bc288a2708cb"
ruleid: 72af37e2-ec32-47dc-992b-bc288a2708cb

tags:
  - attack.execution
  - attack.t1059



status: experimental





date: Sun, 12 Sep 2021 20:00:08 -0500


---

Identifies when a new cloudshell is created inside of Azure portal.

<!--more-->


## Known false-positives

* A new cloudshell may be created by a system administrator.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_new_cloudshell_created.yml))
```yaml
title: Azure New CloudShell Created
id: 72af37e2-ec32-47dc-992b-bc288a2708cb
description: Identifies when a new cloudshell is created inside of Azure portal.
author: Austin Songer
status: experimental
date: 2021/09/21
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message: MICROSOFT.PORTAL/CONSOLES/WRITE
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1059
falsepositives:
 - A new cloudshell may be created by a system administrator. 
 

```
