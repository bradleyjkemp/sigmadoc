---
title: "Azure VPN Connection Modified or Deleted"
aliases:
  - "/rule/61171ffc-d79c-4ae5-8e10-9323dba19cd3"


tags:
  - attack.impact



status: experimental





date: Sun, 8 Aug 2021 22:11:59 -0500


---

Identifies when a VPN connection is modified or deleted.

<!--more-->


## Known false-positives

* VPN Connection being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* VPN Connection modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_vpn_connection_modified_or_deleted.yml))
```yaml
title: Azure VPN Connection Modified or Deleted
id: 61171ffc-d79c-4ae5-8e10-9323dba19cd3
description: Identifies when a VPN connection is modified or deleted.
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/08
references:
    - https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations
logsource:
  product: azure
  service: azure.activitylogs
detection:
    selection:
        properties.message:
            - MICROSOFT.NETWORK/VPNGATEWAYS/VPNCONNECTIONS/WRITE
            - MICROSOFT.NETWORK/VPNGATEWAYS/VPNCONNECTIONS/DELETE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - VPN Connection being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - VPN Connection modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
