---
title: "Use Get-NetTCPConnection"
aliases:
  - "/rule/b366adb4-d63d-422d-8a2c-186463b5ded0"
ruleid: b366adb4-d63d-422d-8a2c-186463b5ded0

tags:
  - attack.discovery
  - attack.t1049



status: experimental





date: Sat, 11 Dec 2021 09:38:20 +0100


---

Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.

<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md#atomic-test-2---system-network-connections-discovery-with-powershell


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_classic/posh_pc_susp_get_nettcpconnection.yml))
```yaml
title: Use Get-NetTCPConnection 
id: b366adb4-d63d-422d-8a2c-186463b5ded0
status: experimental
description: Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md#atomic-test-2---system-network-connections-discovery-with-powershell
author: frack113
date: 2021/12/10
logsource:
    product: windows
    category: ps_classic_start
    definition: fields have to be extract from event
detection:
    selection:
        HostApplication|contains: Get-NetTCPConnection
    condition: selection 
falsepositives:
    - Unknown
level: low
tags:
    - attack.discovery
    - attack.t1049
```
