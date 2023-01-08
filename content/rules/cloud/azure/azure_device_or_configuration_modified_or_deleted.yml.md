---
title: "Azure Device or Configuration Modified or Deleted"
aliases:
  - "/rule/46530378-f9db-4af9-a9e5-889c177d3881"
ruleid: 46530378-f9db-4af9-a9e5-889c177d3881

tags:
  - attack.impact



status: experimental





date: Fri, 3 Sep 2021 22:24:32 -0500


---

Identifies when a device or device configuration in azure is modified or deleted.

<!--more-->


## Known false-positives

* Device or device configuration being modified or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Device or device configuration modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#core-directory


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_device_or_configuration_modified_or_deleted.yml))
```yaml
title: Azure Device or Configuration Modified or Deleted
id: 46530378-f9db-4af9-a9e5-889c177d3881
description: Identifies when a device or device configuration in azure is modified or deleted.
author: Austin Songer @austinsonger
status: experimental
date: 2021/09/03
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#core-directory
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message: 
            - Delete device
            - Delete device configuration
            - Update device
            - Update device configuration
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Device or device configuration being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Device or device configuration modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
