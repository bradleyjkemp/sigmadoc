---
title: "Azure Device No Longer Managed or Compliant"
aliases:
  - "/rule/542b9912-c01f-4e3f-89a8-014c48cdca7d"
ruleid: 542b9912-c01f-4e3f-89a8-014c48cdca7d

tags:
  - attack.impact



status: experimental





date: Fri, 3 Sep 2021 22:23:21 -0500


---

Identifies when a device in azure is no longer managed or compliant

<!--more-->


## Known false-positives

* Administrator may have forgotten to review the device.



## References

* https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#core-directory


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_device_no_longer_managed_or_compliant.yml))
```yaml
title: Azure Device No Longer Managed or Compliant
id: 542b9912-c01f-4e3f-89a8-014c48cdca7d
description: Identifies when a device in azure is no longer managed or compliant
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
            - Device no longer compliant
            - Device no longer managed
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Administrator may have forgotten to review the device. 

```
