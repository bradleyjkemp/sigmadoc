---
title: "Suspicious Network Command"
aliases:
  - "/rule/a29c1813-ab1f-4dde-b489-330b952e91ae"


tags:
  - attack.discovery
  - attack.t1016



status: experimental





date: Tue, 7 Dec 2021 20:41:49 +0100


---

Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems

<!--more-->


## Known false-positives

* administrator, hotline ask to user



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md#atomic-test-1---system-network-configuration-discovery-on-windows


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_network_command.yml))
```yaml
title: Suspicious Network Command
id: a29c1813-ab1f-4dde-b489-330b952e91ae
status: experimental
description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md#atomic-test-1---system-network-configuration-discovery-on-windows
author: frack113
date: 2021/12/07
logsource:
    category: process_creation
    product: windows
detection:
    network_cmd:
        CommandLine|contains: 
            - 'ipconfig /all'
            - 'netsh interface show interface'
            - 'arp -a'
            - 'nbtstat -n'
            - 'net config'
    condition: network_cmd
falsepositives:
    - administrator, hotline ask to user
level: low
tags:
    - attack.discovery
    - attack.t1016

```