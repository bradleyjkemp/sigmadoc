---
title: "Remote PowerShell Session"
aliases:
  - "/rule/c539afac-c12a-46ed-b1bd-5a5567c9f045"
ruleid: c539afac-c12a-46ed-b1bd-5a5567c9f045

tags:
  - attack.execution
  - attack.t1059.001
  - attack.lateral_movement
  - attack.t1021.006



status: test





date: Thu, 24 Oct 2019 15:48:38 +0200


---

Detects remote PowerShell connections by monitoring network outbound connections to ports 5985 or 5986 from a non-network service account.

<!--more-->


## Known false-positives

* Legitimate usage of remote PowerShell, e.g. remote administration and monitoring.



## References

* https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190511223310.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_remote_powershell_session_network.yml))
```yaml
title: Remote PowerShell Session
id: c539afac-c12a-46ed-b1bd-5a5567c9f045
status: test
description: Detects remote PowerShell connections by monitoring network outbound connections to ports 5985 or 5986 from a non-network service account.
author: Roberto Rodriguez @Cyb3rWard0g
references:
  - https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190511223310.html
date: 2019/09/12
modified: 2022/02/16
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationPort:
      - 5985
      - 5986
  filter:
    User|contains: 
      - 'AUTHORI'
      - 'AUTORI'
  condition: selection and not filter
falsepositives:
  - Legitimate usage of remote PowerShell, e.g. remote administration and monitoring.
level: high
tags:
  - attack.execution
  - attack.t1059.001
  - attack.lateral_movement
  - attack.t1021.006

```
