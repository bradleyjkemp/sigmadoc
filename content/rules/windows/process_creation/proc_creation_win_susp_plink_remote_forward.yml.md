---
title: "Suspicious Plink Remote Forwarding"
aliases:
  - "/rule/48a61b29-389f-4032-b317-b30de6b95314"
ruleid: 48a61b29-389f-4032-b317-b30de6b95314

tags:
  - attack.command_and_control
  - attack.t1572
  - attack.lateral_movement
  - attack.t1021.001



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects suspicious Plink tunnel remote forarding to a local port

<!--more-->


## Known false-positives

* Administrative activity using a remote port forwarding to a local port



## References

* https://www.real-sec.com/2019/04/bypassing-network-restrictions-through-rdp-tunneling/
* https://medium.com/@informationsecurity/remote-ssh-tunneling-with-plink-exe-7831072b3d7d


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_susp_plink_remote_forward.yml))
```yaml
title: Suspicious Plink Remote Forwarding
id: 48a61b29-389f-4032-b317-b30de6b95314
status: experimental
description: Detects suspicious Plink tunnel remote forarding to a local port
references:
    - https://www.real-sec.com/2019/04/bypassing-network-restrictions-through-rdp-tunneling/
    - https://medium.com/@informationsecurity/remote-ssh-tunneling-with-plink-exe-7831072b3d7d
author: Florian Roth
date: 2021/01/19
tags:
    - attack.command_and_control
    - attack.t1572
    - attack.lateral_movement
    - attack.t1021.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Description: 'Command-line SSH, Telnet, and Rlogin client'
        CommandLine|contains: ' -R '
    condition: selection
falsepositives:
    - Administrative activity using a remote port forwarding to a local port
level: high

```
