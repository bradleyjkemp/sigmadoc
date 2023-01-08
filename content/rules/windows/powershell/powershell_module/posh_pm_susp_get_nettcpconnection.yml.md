---
title: "Use Get-NetTCPConnection"
aliases:
  - "/rule/aff815cc-e400-4bf0-a47a-5d8a2407d4e1"
ruleid: aff815cc-e400-4bf0-a47a-5d8a2407d4e1

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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/powershell/powershell_module/posh_pm_susp_get_nettcpconnection.yml))
```yaml
title: Use Get-NetTCPConnection 
id: aff815cc-e400-4bf0-a47a-5d8a2407d4e1
status: experimental
description: Adversaries may attempt to get a listing of network connections to or from the compromised system they are currently accessing or from remote systems by querying for information over the network.
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1049/T1049.md#atomic-test-2---system-network-connections-discovery-with-powershell
author: frack113
date: 2021/12/10
logsource:
    product: windows
    category: ps_module
    definition: PowerShell Module Logging must be enabled
detection:
    selection:
        ContextInfo|contains: 'Get-NetTCPConnection'
    condition: selection 
falsepositives:
    - Unknown
level: low
tags:
    - attack.discovery
    - attack.t1049
```
