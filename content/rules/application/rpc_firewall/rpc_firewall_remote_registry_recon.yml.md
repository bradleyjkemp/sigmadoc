---
title: "Remote Registry Recon"
aliases:
  - "/rule/d8ffe17e-04be-4886-beb9-c1dd1944b9a8"
ruleid: d8ffe17e-04be-4886-beb9-c1dd1944b9a8



status: experimental





date: Mon, 10 Jan 2022 18:04:43 +0200


---

Detects remote RPC calls to collect information

<!--more-->


## Known false-positives

* Remote administration of registry values



## References

* https://attack.mitre.org/tactics/TA0007/
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78
* https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-RRP.md
* https://github.com/zeronetworks/rpcfirewall
* https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/application/rpc_firewall/rpc_firewall_remote_registry_recon.yml))
```yaml
title: Remote Registry Recon
id: d8ffe17e-04be-4886-beb9-c1dd1944b9a8
description: Detects remote RPC calls to collect information
references:
    - https://attack.mitre.org/tactics/TA0007/
    - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp/0fa3191d-bb79-490a-81bd-54c2601b7a78
    - https://github.com/jsecurity101/MSRPC-to-ATTACK/blob/main/documents/MS-RRP.md
    - https://github.com/zeronetworks/rpcfirewall
    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/
status: experimental
author: Sagie Dulce, Dekel Paz
date: 2022/01/01
modified: 2022/01/01
logsource:
    product: rpc_firewall
    category: application
    definition: 'Requirements: install and apply the RPC Firewall to all processes with "audit:true action:block uuid:338cd001-2244-31f1-aaaa-900038001003"'
detection:
    selection:
        EventLog: RPCFW
        EventID: 3
        InterfaceUuid: 338cd001-2244-31f1-aaaa-900038001003
    filter:
      OpNum:
        - 6
        - 7
        - 8
        - 13
        - 18
        - 19
        - 21
        - 22
        - 23
        - 35
    condition: selection and not filter
falsepositives:
    - Remote administration of registry values
level: high

```
