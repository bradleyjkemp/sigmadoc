---
title: "Remote PowerShell Sessions"
aliases:
  - "/rule/13acf386-b8c6-4fe0-9a6e-c4756b974698"

tags:
  - attack.execution
  - attack.t1086
  - attack.t1059.001



status: experimental



level: high



date: Thu, 24 Oct 2019 15:48:38 +0200


---

Detects basic PowerShell Remoting by monitoring for network inbound connections to ports 5985 OR 5986

<!--more-->


## Known false-positives

* Legitimate use of remote PowerShell execution



## References

* https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md


## Raw rule
```yaml
title: Remote PowerShell Sessions
id: 13acf386-b8c6-4fe0-9a6e-c4756b974698
description: Detects basic PowerShell Remoting by monitoring for network inbound connections to ports 5985 OR 5986
status: experimental
date: 2019/09/12
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://github.com/Cyb3rWard0g/ThreatHunter-Playbook/tree/master/playbooks/windows/02_execution/T1086_powershell/powershell_remote_session.md
tags:
    - attack.execution
    - attack.t1086          # an old one
    - attack.t1059.001
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 5156
        DestPort:
            - 5985
            - 5986
        LayerRTID: 44
    condition: selection
falsepositives:
    - Legitimate use of remote PowerShell execution
level: high

```
