---
title: "Azure Keyvault Key Modified or Deleted"
aliases:
  - "/rule/80eeab92-0979-4152-942d-96749e11df40"


tags:
  - attack.impact
  - attack.credential_access
  - attack.t1552
  - attack.t1552.001



status: experimental





date: Mon, 16 Aug 2021 23:50:56 -0500


---

Identifies when a Keyvault Key is modified or deleted in Azure.

<!--more-->


## Known false-positives

* Key being modified or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Key modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_keyvault_key_modified_or_deleted.yml))
```yaml
title: Azure Keyvault Key Modified or Deleted
id: 80eeab92-0979-4152-942d-96749e11df40
description: Identifies when a Keyvault Key is modified or deleted in Azure.
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
            - MICROSOFT.KEYVAULT/VAULTS/KEYS/UPDATE/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/KEYS/CREATE
            - MICROSOFT.KEYVAULT/VAULTS/KEYS/CREATE/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/KEYS/IMPORT/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/KEYS/RECOVER/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/KEYS/RESTORE/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/KEYS/DELETE
            - MICROSOFT.KEYVAULT/VAULTS/KEYS/BACKUP/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/KEYS/PURGE/ACTION
    condition: selection
level: medium
tags:
    - attack.impact
    - attack.credential_access
    - attack.t1552
    - attack.t1552.001
falsepositives:
 - Key being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Key modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
