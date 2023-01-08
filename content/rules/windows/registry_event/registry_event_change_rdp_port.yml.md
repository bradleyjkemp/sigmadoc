---
title: "Changing RDP Port to Non Standard Number"
aliases:
  - "/rule/509e84b9-a71a-40e0-834f-05470369bd1e"
ruleid: 509e84b9-a71a-40e0-834f-05470369bd1e

tags:
  - attack.persistence
  - attack.t1547.010



status: experimental





date: Sat, 1 Jan 2022 08:42:40 +0100


---

Remote desktop is a common feature in operating systems.
It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system.
Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).


<!--more-->


## Known false-positives

* Unknown



## References

* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md#atomic-test-1---rdp-to-domaincontroller


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/registry_event/registry_event_change_rdp_port.yml))
```yaml
title: Changing RDP Port to Non Standard Number
id: 509e84b9-a71a-40e0-834f-05470369bd1e
description: |
  Remote desktop is a common feature in operating systems.
  It allows a user to log into an interactive session with a system desktop graphical user interface on a remote system.
  Microsoft refers to its implementation of the Remote Desktop Protocol (RDP) as Remote Desktop Services (RDS).
author: frack113
date: 2022/01/01
status: experimental
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1021.001/T1021.001.md#atomic-test-1---rdp-to-domaincontroller
logsource:
    category: registry_event
    product: windows
detection:
    selection:
        EventType: SetValue
        TargetObject: HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp\PortNumber
    filter:    
        Details: DWORD (0x00000d3d)
    condition: selection and not filter
falsepositives:
    - Unknown
level: high
tags:
  - attack.persistence
  - attack.t1547.010

```
