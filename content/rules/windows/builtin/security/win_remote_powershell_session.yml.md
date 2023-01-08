---
title: "Remote PowerShell Sessions Network Connections (WinRM)"
aliases:
  - "/rule/13acf386-b8c6-4fe0-9a6e-c4756b974698"
ruleid: 13acf386-b8c6-4fe0-9a6e-c4756b974698

tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 24 Oct 2019 15:48:38 +0200


---

Detects basic PowerShell Remoting (WinRM) by monitoring for network inbound connections to ports 5985 OR 5986

<!--more-->


## Known false-positives

* Legitimate use of remote PowerShell execution



## References

* https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190511223310.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/builtin/security/win_remote_powershell_session.yml))
```yaml
title: Remote PowerShell Sessions Network Connections (WinRM)
id: 13acf386-b8c6-4fe0-9a6e-c4756b974698
description: Detects basic PowerShell Remoting (WinRM) by monitoring for network inbound connections to ports 5985 OR 5986
status: experimental
date: 2019/09/12
modified: 2021/05/21
author: Roberto Rodriguez @Cyb3rWard0g
references:
    - https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190511223310.html
tags:
    - attack.execution
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
