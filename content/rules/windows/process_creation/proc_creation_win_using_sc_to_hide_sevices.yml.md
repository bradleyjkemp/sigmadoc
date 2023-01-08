---
title: "Abuse of Service Permissions to Hide Services in Tools"
aliases:
  - "/rule/a537cfc3-4297-4789-92b5-345bfd845ad0"
ruleid: a537cfc3-4297-4789-92b5-345bfd845ad0

tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1574.011



status: experimental





date: Mon, 20 Dec 2021 23:36:23 +0100


---

Detection of sc.exe utility adding a new service with special permission which hides that service.

<!--more-->


## Known false-positives

* Intended use of hidden services



## References

* https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
* https://www.sans.org/blog/red-team-tactics-hiding-windows-services/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_using_sc_to_hide_sevices.yml))
```yaml
title: Abuse of Service Permissions to Hide Services in Tools
id: a537cfc3-4297-4789-92b5-345bfd845ad0
status: experimental
description: Detection of sc.exe utility adding a new service with special permission which hides that service.
author: Andreas Hunkeler (@Karneades)
references:
  - https://blog.talosintelligence.com/2021/10/threat-hunting-in-large-datasets-by.html
  - https://www.sans.org/blog/red-team-tactics-hiding-windows-services/
date: 2021/12/20
logsource:
  category: process_creation
  product: windows
detection:
  sc:
    Image|endswith: '\sc.exe'
  cli:
    CommandLine|contains|all:
      - 'sdset'
      - 'DCLCWPDTSD'
  condition: sc and cli
falsepositives:
  - Intended use of hidden services
level: high
tags:
  - attack.persistence
  - attack.defense_evasion
  - attack.privilege_escalation
  - attack.t1574.011

```
