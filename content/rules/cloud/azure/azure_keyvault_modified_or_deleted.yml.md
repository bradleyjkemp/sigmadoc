---
title: "Azure Key Vault Modified or Deleted."
aliases:
  - "/rule/459a2970-bb84-4e6a-a32e-ff0fbd99448d"
ruleid: 459a2970-bb84-4e6a-a32e-ff0fbd99448d

tags:
  - attack.impact
  - attack.credential_access
  - attack.t1552
  - attack.t1552.001



status: experimental





date: Mon, 16 Aug 2021 23:41:43 -0500


---

Identifies when a key vault is modified or deleted.

<!--more-->


## Known false-positives

* Key Vault being modified or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Key Vault modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_keyvault_modified_or_deleted.yml))
```yaml
title: Azure Key Vault Modified or Deleted.
id: 459a2970-bb84-4e6a-a32e-ff0fbd99448d
description: Identifies when a key vault is modified or deleted.
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
            - MICROSOFT.KEYVAULT/VAULTS/WRITE
            - MICROSOFT.KEYVAULT/VAULTS/DELETE
            - MICROSOFT.KEYVAULT/VAULTS/DEPLOY/ACTION
            - MICROSOFT.KEYVAULT/VAULTS/ACCESSPOLICIES/WRITE
    condition: selection
level: medium
tags:
    - attack.impact
    - attack.credential_access
    - attack.t1552
    - attack.t1552.001
falsepositives:
 - Key Vault being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Key Vault modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```