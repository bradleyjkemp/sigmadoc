---
title: "Azure Service Principal Removed"
aliases:
  - "/rule/448fd1ea-2116-4c62-9cde-a92d120e0f08"


tags:
  - attack.defense_evasion



status: experimental





date: Thu, 2 Sep 2021 20:48:35 -0500


---

Identifies when a service principal was removed in Azure.

<!--more-->


## Known false-positives

* Service principal being removed may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Service principal removed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#application-proxy


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_service_principal_removed.yml))
```yaml
title: Azure Service Principal Removed
id: 448fd1ea-2116-4c62-9cde-a92d120e0f08
description: Identifies when a service principal was removed in Azure.
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
        properties.message: Remove service principal
    condition: selection
level: medium
tags:
    - attack.defense_evasion
falsepositives:
 - Service principal being removed may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Service principal removed from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
