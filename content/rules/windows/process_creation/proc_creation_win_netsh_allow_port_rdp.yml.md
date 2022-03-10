---
title: "Netsh RDP Port Opening"
aliases:
  - "/rule/01aeb693-138d-49d2-9403-c4f52d7d3d62"


tags:
  - attack.defense_evasion
  - attack.t1562.004



status: test





date: Fri, 5 Jun 2020 13:18:03 -0400


---

Detects netsh commands that opens the port 3389 used for RDP, used in Sarwent Malware

<!--more-->


## Known false-positives

* Legitimate administration



## References

* https://labs.sentinelone.com/sarwent-malware-updates-command-detonation/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_netsh_allow_port_rdp.yml))
```yaml
title: Netsh RDP Port Opening
id: 01aeb693-138d-49d2-9403-c4f52d7d3d62
status: test
description: Detects netsh commands that opens the port 3389 used for RDP, used in Sarwent Malware
author: Sander Wiebing
references:
  - https://labs.sentinelone.com/sarwent-malware-updates-command-detonation/
date: 2020/05/23
modified: 2021/11/27
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    CommandLine|contains|all:
      - netsh
      - firewall add portopening
      - tcp 3389
  selection2:
    CommandLine|contains|all:
      - netsh
      - advfirewall firewall add rule
      - action=allow
      - protocol=TCP
      - localport=3389
  condition: 1 of selection*
falsepositives:
  - Legitimate administration
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.004

```
