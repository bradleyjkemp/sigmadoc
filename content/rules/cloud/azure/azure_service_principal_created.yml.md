---
title: "Azure Service Principal Created"
aliases:
  - "/rule/0ddcff6d-d262-40b0-804b-80eb592de8e3"
ruleid: 0ddcff6d-d262-40b0-804b-80eb592de8e3

tags:
  - attack.defense_evasion



status: experimental





date: Thu, 2 Sep 2021 20:48:35 -0500


---

Identifies when a service principal is created in Azure.

<!--more-->


## Known false-positives

* Service principal being created may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Service principal created from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#application-proxy


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_service_principal_created.yml))
```yaml
title: Azure Service Principal Created
id: 0ddcff6d-d262-40b0-804b-80eb592de8e3
description: Identifies when a service principal is created in Azure.
author: Austin Songer @austinsonger
status: experimental
date: 2021/09/02
references:
    - https://docs.microsoft.com/en-us/azure/active-directory/reports-monitoring/reference-audit-activities#application-proxy
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message: 'Add service principal'
    condition: selection
level: medium
tags:
    - attack.defense_evasion
falsepositives:
 - Service principal being created may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Service principal created from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
