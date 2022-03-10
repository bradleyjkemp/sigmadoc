---
title: "Interactive Logon to Server Systems"
aliases:
  - "/rule/3ff152b2-1388-4984-9cd9-a323323fdadf"


tags:
  - attack.lateral_movement
  - attack.t1078



status: test





date: Fri, 17 Mar 2017 09:44:24 +0100


---

Detects interactive console logons to Server Systems

<!--more-->


## Known false-positives

* Administrative activity via KVM or ILO board




## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_susp_interactive_logons.yml))
```yaml
title: Interactive Logon to Server Systems
id: 3ff152b2-1388-4984-9cd9-a323323fdadf
status: test
description: Detects interactive console logons to Server Systems
author: Florian Roth
date: 2017/03/17
modified: 2021/11/27
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 528
      - 529
      - 4624
      - 4625
    LogonType: 2
    ComputerName:
      - '%ServerSystems%'
      - '%DomainControllers%'
  filter:
    LogonProcessName: Advapi
    ComputerName: '%Workstations%'
  condition: selection and not filter
falsepositives:
  - Administrative activity via KVM or ILO board
level: medium
tags:
  - attack.lateral_movement
  - attack.t1078

```
