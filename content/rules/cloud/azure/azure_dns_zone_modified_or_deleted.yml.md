---
title: "Azure DNS Zone Modified or Deleted"
aliases:
  - "/rule/af6925b0-8826-47f1-9324-337507a0babd"
ruleid: af6925b0-8826-47f1-9324-337507a0babd

tags:
  - attack.impact



status: experimental





date: Sun, 8 Aug 2021 22:42:08 -0500


---

Identifies when DNS zone is modified or deleted.

<!--more-->


## Known false-positives

* DNS zone modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* DNS zone modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_dns_zone_modified_or_deleted.yml))
```yaml
title: Azure DNS Zone Modified or Deleted
id: af6925b0-8826-47f1-9324-337507a0babd
description: Identifies when DNS zone is modified or deleted.
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/08
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations#microsoftkubernetes
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message|startswith: MICROSOFT.NETWORK/DNSZONES
        properties.message|endswith:
            - /WRITE
            - /DELETE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - DNS zone modified and deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - DNS zone modification from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
