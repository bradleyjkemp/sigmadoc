---
title: "Remote DCOM/WMI Lateral Movement"
aliases:
  - "/rule/68050b10-e477-4377-a99b-3721b422d6ef"
ruleid: 68050b10-e477-4377-a99b-3721b422d6ef

tags:
  - attack.lateral_movement
  - attack.t1021.003
  - attack.t1047



status: experimental





date: Mon, 10 Jan 2022 18:04:43 +0200


---

Detects remote RPC calls that performs remote DCOM operations. These could be abused for lateral movement via DCOM or WMI.

<!--more-->


## Known false-positives

* Some administrative tasks on remote host



## References

* https://attack.mitre.org/tactics/TA0008/
* https://attack.mitre.org/techniques/T1021/003/
* https://attack.mitre.org/techniques/T1047/
* https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9
* https://github.com/zeronetworks/rpcfirewall
* https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/application/rpc_firewall/rpc_firewall_remote_dcom_or_wmi.yml))
```yaml
title: Remote DCOM/WMI Lateral Movement
id: 68050b10-e477-4377-a99b-3721b422d6ef
description: Detects remote RPC calls that performs remote DCOM operations. These could be abused for lateral movement via DCOM or WMI.
references:
    - https://attack.mitre.org/tactics/TA0008/
    - https://attack.mitre.org/techniques/T1021/003/
    - https://attack.mitre.org/techniques/T1047/
    - https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9
    - https://github.com/zeronetworks/rpcfirewall
    - https://zeronetworks.com/blog/stopping_lateral_movement_via_the_rpc_firewall/
tags:
    - attack.lateral_movement
    - attack.t1021.003
    - attack.t1047
status: experimental
author: Sagie Dulce, Dekel Paz
date: 2022/01/01
modified: 2022/01/01
logsource:
    product: rpc_firewall
    category: application
    definition: 'Requirements: install and apply the RPC Firewall to all processes with "audit:true action:block uuid:367abb81-9844-35f1-ad32-98f038001003'
detection:
    selection:
        EventLog: RPCFW
        EventID: 3
        InterfaceUuid:
          - 4d9f4ab8-7d1c-11cf-861e-0020af6e7c57
          - 99fcfec4-5260-101b-bbcb-00aa0021347a
          - 000001a0-0000-0000-c000-000000000046
          - 00000131-0000-0000-c000-000000000046
          - 00000143-0000-0000-c000-000000000046
          - 00000000-0000-0000-c000-000000000046
    condition: selection
falsepositives:
    - Some administrative tasks on remote host
level: high

```
