---
title: "Netsh RDP Port Forwarding"
aliases:
  - "/rule/782d6f3e-4c5d-4b8c-92a3-1d05fed72e63"
ruleid: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63

tags:
  - attack.lateral_movement
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1090



status: test





---

Detects netsh commands that configure a port forwarding of port 3389 used for RDP

<!--more-->


## Known false-positives

* Legitimate administration



## References

* https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_netsh_port_fwd_3389.yml))
```yaml
title: Netsh RDP Port Forwarding
id: 782d6f3e-4c5d-4b8c-92a3-1d05fed72e63
status: test
description: Detects netsh commands that configure a port forwarding of port 3389 used for RDP
author: Florian Roth, oscd.community
references:
  - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
date: 2019/01/29
modified: 2022/01/07
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\netsh.exe'
    CommandLine|contains|all:
      - 'i'
      - ' p'
      - '=3389'
      - ' c'
  condition: selection
falsepositives:
  - Legitimate administration
level: high
tags:
  - attack.lateral_movement
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1090

```
