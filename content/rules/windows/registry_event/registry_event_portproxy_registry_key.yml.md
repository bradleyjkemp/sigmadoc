---
title: "PortProxy Registry Key"
aliases:
  - "/rule/a54f842a-3713-4b45-8c84-5f136fdebd3c"
ruleid: a54f842a-3713-4b45-8c84-5f136fdebd3c

tags:
  - attack.lateral_movement
  - attack.defense_evasion
  - attack.command_and_control
  - attack.t1090



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects the modification of PortProxy registry key which is used for port forwarding. For command execution see rule win_netsh_port_fwd.yml.

<!--more-->


## Known false-positives

* WSL2 network bridge PowerShell script used for WSL/Kubernetes/Docker (e.g. https://github.com/microsoft/WSL/issues/4150#issuecomment-504209723)
* Synergy Software KVM (https://symless.com/synergy)



## References

* https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
* https://adepts.of0x.cc/netsh-portproxy-code/
* https://www.dfirnotes.net/portproxy_detection/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_portproxy_registry_key.yml))
```yaml
title: PortProxy Registry Key
id: a54f842a-3713-4b45-8c84-5f136fdebd3c
status: experimental
description: Detects the modification of PortProxy registry key which is used for port forwarding. For command execution see rule win_netsh_port_fwd.yml.
references:
    - https://www.fireeye.com/blog/threat-research/2019/01/bypassing-network-restrictions-through-rdp-tunneling.html
    - https://adepts.of0x.cc/netsh-portproxy-code/
    - https://www.dfirnotes.net/portproxy_detection/
date: 2021/06/22
modified: 2021/09/13
tags:
    - attack.lateral_movement
    - attack.defense_evasion
    - attack.command_and_control
    - attack.t1090
author: Andreas Hunkeler (@Karneades)
logsource:
    category: registry_event
    product: windows
detection:
    selection_registry:
        TargetObject: 'HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp'
    condition: selection_registry
falsepositives:
    - WSL2 network bridge PowerShell script used for WSL/Kubernetes/Docker (e.g. https://github.com/microsoft/WSL/issues/4150#issuecomment-504209723)
    - Synergy Software KVM (https://symless.com/synergy)
level: medium

```
