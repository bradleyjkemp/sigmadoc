---
title: "Azure Application Security Group Modified or Deleted"
aliases:
  - "/rule/835747f1-9329-40b5-9cc3-97d465754ce6"


tags:
  - attack.impact



status: experimental





date: Mon, 16 Aug 2021 23:31:45 -0500


---

Identifies when a application security group is modified or deleted.

<!--more-->


## Known false-positives

* Application security group being modified or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Application security group modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_application_security_group_modified_or_deleted.yml))
```yaml
title: Azure Application Security Group Modified or Deleted
id: 835747f1-9329-40b5-9cc3-97d465754ce6
description: Identifies when a application security group is modified or deleted.
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
            - MICROSOFT.NETWORK/APPLICATIONSECURITYGROUPS/WRITE
            - MICROSOFT.NETWORK/APPLICATIONSECURITYGROUPS/DELETE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Application security group being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Application security group modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
