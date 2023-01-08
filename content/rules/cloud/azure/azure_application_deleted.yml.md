---
title: "Azure Application Deleted"
aliases:
  - "/rule/410d2a41-1e6d-452f-85e5-abdd8257a823"
ruleid: 410d2a41-1e6d-452f-85e5-abdd8257a823

tags:
  - attack.defense_evasion



status: experimental





date: Thu, 2 Sep 2021 20:48:35 -0500


---

Identifies when a application is deleted in Azure.

<!--more-->


## Known false-positives

* Application being deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Application deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#application-proxy


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_application_deleted.yml))
```yaml
title: Azure Application Deleted
id: 410d2a41-1e6d-452f-85e5-abdd8257a823
description: Identifies when a application is deleted in Azure.
author: Austin Songer @austinsonger
status: experimental
date: 2021/09/03
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#application-proxy
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message:
            - Delete application
            - Hard Delete application
    condition: selection
level: medium
tags:
    - attack.defense_evasion
falsepositives:
 - Application being deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Application deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
