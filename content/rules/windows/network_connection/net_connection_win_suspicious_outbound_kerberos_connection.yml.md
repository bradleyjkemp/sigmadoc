---
title: "Suspicious Outbound Kerberos Connection"
aliases:
  - "/rule/e54979bd-c5f9-4d6c-967b-a04b19ac4c74"


tags:
  - attack.credential_access
  - attack.t1558
  - attack.lateral_movement
  - attack.t1550.003



status: test





date: Tue, 29 Oct 2019 03:44:22 +0300


---

Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.

<!--more-->


## Known false-positives

* Other browsers



## References

* https://github.com/GhostPack/Rubeus


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_suspicious_outbound_kerberos_connection.yml))
```yaml
title: Suspicious Outbound Kerberos Connection
id: e54979bd-c5f9-4d6c-967b-a04b19ac4c74
status: test
description: Detects suspicious outbound network activity via kerberos default port indicating possible lateral movement or first stage PrivEsc via delegation.
author: Ilyas Ochkov, oscd.community
references:
  - https://github.com/GhostPack/Rubeus
date: 2019/10/24
modified: 2021/12/02
logsource:
  category: network_connection
  product: windows
detection:
  selection:
    DestinationPort: 88
    Initiated: 'true'
  filter:
    Image|endswith:
      - '\lsass.exe'
      - '\opera.exe'
      - '\chrome.exe'
      - '\firefox.exe'
      - '\tomcat\bin\tomcat8.exe'
  condition: selection and not filter
falsepositives:
  - Other browsers
level: high
tags:
  - attack.credential_access
  - attack.t1558
  - attack.lateral_movement
  - attack.t1550.003

```