---
title: "Azure Keyvault Secrets Modified or Deleted"
aliases:
  - "/rule/b831353c-1971-477b-abb6-2828edc3bca1"


tags:
  - attack.impact
  - attack.credential_access
  - attack.t1552
  - attack.t1552.001



status: experimental





date: Mon, 16 Aug 2021 23:54:57 -0500


---

Identifies when secrets are modified or deleted in Azure.

<!--more-->


## Known false-positives

* Secrets being modified or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Secrets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_keyvault_secrets_modified_or_deleted.yml))
```yaml
title: Azure Keyvault Secrets Modified or Deleted
id: b831353c-1971-477b-abb6-2828edc3bca1
description: Identifies when secrets are modified or deleted in Azure.
author: Austin Songer @austinsonger
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
            - MICROSOFT.KEYVAULT/VAULTS/SECRETS/WRITE
            - MICROSOFT.KEYVAULT/VAULTS/SECRETS/DELETE
            - MICROSOFT.KEYVAULT/VAULTS/SECRETS/BACKUP/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/SECRETS/PURGE/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/SECRETS/UPDATE/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/SECRETS/RECOVER/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/SECRETS/RESTORE/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/SECRETS/SETSECRET/ACTION
    condition: selection
level: medium
tags:
    - attack.impact
    - attack.credential_access
    - attack.t1552
    - attack.t1552.001
falsepositives:
 - Secrets being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Secrets modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
