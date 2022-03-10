---
title: "Azure Point-to-site VPN Modified or Deleted"
aliases:
  - "/rule/d9557b75-267b-4b43-922f-a775e2d1f792"


tags:
  - attack.impact



status: experimental





date: Sun, 8 Aug 2021 22:47:35 -0500


---

Identifies when a Point-to-site VPN is Modified or Deleted.

<!--more-->


## Known false-positives

* Point-to-site VPN being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* Point-to-site VPN modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://docs.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/azure/azure_network_p2s_vpn_modified_or_deleted.yml))
```yaml
title: Azure Point-to-site VPN Modified or Deleted
id: d9557b75-267b-4b43-922f-a775e2d1f792
description: Identifies when a Point-to-site VPN is Modified or Deleted.
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
            - MICROSOFT.NETWORK/P2SVPNGATEWAYS/WRITE
            - MICROSOFT.NETWORK/P2SVPNGATEWAYS/DELETE
            - MICROSOFT.NETWORK/P2SVPNGATEWAYS/RESET/ACTION
            - MICROSOFT.NETWORK/P2SVPNGATEWAYS/GENERATEVPNPROFILE/ACTION
            - MICROSOFT.NETWORK/P2SVPNGATEWAYS/DISCONNECTP2SVPNCONNECTIONS/ACTION
            - MICROSOFT.NETWORK/P2SVPNGATEWAYS/PROVIDERS/MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - Point-to-site VPN being modified or deleted may be performed by a system administrator. Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - Point-to-site VPN modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
