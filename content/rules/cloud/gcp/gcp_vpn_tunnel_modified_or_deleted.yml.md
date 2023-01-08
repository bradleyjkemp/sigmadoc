---
title: "Google Cloud VPN Tunnel Modified or Deleted"
aliases:
  - "/rule/99980a85-3a61-43d3-ac0f-b68d6b4797b1"
ruleid: 99980a85-3a61-43d3-ac0f-b68d6b4797b1

tags:
  - attack.impact



status: experimental





date: Sun, 15 Aug 2021 14:37:08 -0500


---

Identifies when a VPN Tunnel Modified or Deleted in Google Cloud.

<!--more-->


## Known false-positives

* VPN Tunnel being modified or deleted may be performed by a system administrator.
* Verify whether the user identity, user agent, and/or hostname should be making changes in your environment.
* VPN Tunnel modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.



## References

* https://any-api.com/googleapis_com/compute/docs/vpnTunnels


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/cloud/gcp/gcp_vpn_tunnel_modified_or_deleted.yml))
```yaml
title: Google Cloud VPN Tunnel Modified or Deleted
id: 99980a85-3a61-43d3-ac0f-b68d6b4797b1
description: Identifies when a VPN Tunnel Modified or Deleted in Google Cloud. 
author: Austin Songer @austinsonger
status: experimental
date: 2021/08/16
references:
    - https://any-api.com/googleapis_com/compute/docs/vpnTunnels
logsource:
  product: gcp
  service: gcp.audit
detection:
    selection:
        gcp.audit.method_name: 
            - compute.vpnTunnels.insert
            - compute.vpnTunnels.delete
    condition: selection
level: medium
tags:
    - attack.impact
falsepositives:
 - VPN Tunnel being modified or deleted may be performed by a system administrator. 
 - Verify whether the user identity, user agent, and/or hostname should be making changes in your environment. 
 - VPN Tunnel modified or deleted from unfamiliar users should be investigated. If known behavior is causing false positives, it can be exempted from the rule.

```
