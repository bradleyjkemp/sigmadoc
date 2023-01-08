---
title: "Suspicious Netsh Discovery Command"
aliases:
  - "/rule/0e4164da-94bc-450d-a7be-a4b176179f1f"
ruleid: 0e4164da-94bc-450d-a7be-a4b176179f1f

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

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md#atomic-test-2---list-windows-firewall-rules


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_netsh_command.yml))
```yaml
title: Suspicious Netsh Discovery Command
id: 0e4164da-94bc-450d-a7be-a4b176179f1f
status: experimental
description: Adversaries may look for details about the network configuration and settings of systems they access or through information discovery of remote systems
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1016/T1016.md#atomic-test-2---list-windows-firewall-rules
author: frack113
date: 2021/12/07
logsource:
    category: process_creation
    product: windows
detection:
    network_cmd:
        CommandLine|contains|all: 
            - 'netsh '
            - 'advfirewall '
            - 'firewall '
            - 'show '
            - 'rule '
            - 'name=all'
    condition: network_cmd
falsepositives:
    - administrator, hotline ask to user
level: low
tags:
    - attack.discovery
    - attack.t1016

```
