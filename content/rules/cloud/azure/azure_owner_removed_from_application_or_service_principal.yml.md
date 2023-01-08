---
title: "Azure Owner Removed From Application or Service Principal"
aliases:
  - "/rule/636e30d5-3736-42ea-96b1-e6e2f8429fd6"
ruleid: 636e30d5-3736-42ea-96b1-e6e2f8429fd6

tags:
  - attack.defense_evasion



status: experimental





date: Fri, 3 Sep 2021 22:23:59 -0500


---

Identifies when a owner is was removed from a application or service principal in Azure.

<!--more-->


## Known false-positives

* Owner being removed may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Owner removed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#application-proxy


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_owner_removed_from_application_or_service_principal.yml))
```yaml
title: Azure Owner Removed From Application or Service Principal
id: 636e30d5-3736-42ea-96b1-e6e2f8429fd6
description: Identifies when a owner is was removed from a application or service principal in Azure.
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
            - Remove owner from service principal
            - Remove owner from application
    condition: selection
level: medium
tags:
    - attack.defense_evasion
falsepositives:
 - Owner being removed may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Owner removed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
