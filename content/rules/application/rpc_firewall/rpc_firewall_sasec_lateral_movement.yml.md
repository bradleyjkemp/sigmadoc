---
title: "Remote Schedule Task Lateral Movement via SASec"
aliases:
  - "/rule/aff229ab-f8cd-447b-b215-084d11e79eb0"
ruleid: aff229ab-f8cd-447b-b215-084d11e79eb0

tags:
  - attack.lateral_movement
  - attack.t1053
  - attack.t1053.002



status: experimental





date: Mon, 10 Jan 2022 18:04:43 +0200


---

Detects remote RPC calls to create or execute a scheduled task via SASec

<!--more-->


## Known false-positives

* unknown



## References

* https://attack.mitre.org/techniques/T1053/
* https://attack.mitre.org/tactics/TA0008/
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
* https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-TSCH.md
* https://github.com/zeronetworks/rpcfirewall
* https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/application/rpc_firewall/rpc_firewall_sasec_lateral_movement.yml))
```yaml
title: Remote Schedule Task Lateral Movement via SASec
id: aff229ab-f8cd-447b-b215-084d11e79eb0
description: Detects remote RPC calls to create or execute a scheduled task via SASec
references:
    - https://attack.mitre.org/techniques/T1053/
    - https://attack.mitre.org/tactics/TA0008/
    - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/d1058a28-7e02-4948-8b8d-4a347fa64931
    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-TSCH.md
    - https://github.com/zeronetworks/rpcfirewall
    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/
tags:
    - attack.lateral_movement
    - attack.t1053
    - attack.t1053.002
status: experimental
author: Sagie Dulce, Dekel Paz
date: 2022/01/01
modified: 2022/01/01
logsource:
    product: rpc_firewall
    category: application
    definition: 'Requirements: install and apply the RPC Firewall to all processes with "audit:true action:block uuid:378e52b0-c0a9-11cf-822d-00aa0051e40f"'
detection:
    selection:
        EventLog: RPCFW
        EventID: 3
        InterfaceUuid: 378e52b0-c0a9-11cf-822d-00aa0051e40f
        OpNum:
          - 0
          - 1
    condition: selection
falsepositives:
    - unknown
level: high

```
