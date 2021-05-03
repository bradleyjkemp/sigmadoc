---
title: "Suspicious C2 Activities"
aliases:
  - "/rule/f7158a64-6204-4d6d-868a-6e6378b467e0"

tags:
  - attack.command_and_control



date: Fri, 5 Jun 2020 13:18:03 -0400


---

Detects suspicious activities as declared by Florian Roth in its 'Best Practice Auditd Configuration'. This includes the detection of the following commands; wget, curl, base64, nc, netcat, ncat, ssh, socat, wireshark, rawshark, rdesktop, nmap. These commands match a few techniques from the tactics "Command and Control", including not exhaustively the following; Application Layer Protocol (T1071), Non-Application Layer Protocol (T1095), Data Encoding (T1132)

<!--more-->


## Known false-positives

* Admin or User activity



## References

* https://github.com/Neo23x0/auditd


## Raw rule
```yaml
title: Suspicious C2 Activities
id: f7158a64-6204-4d6d-868a-6e6378b467e0
status: experimental
description: Detects suspicious activities as declared by Florian Roth in its 'Best Practice Auditd Configuration'. This includes the detection of the following commands; wget, curl, base64, nc, netcat, ncat, ssh, socat, wireshark, rawshark, rdesktop, nmap. These commands match a few techniques from the tactics "Command and Control", including not exhaustively the following; Application Layer Protocol (T1071), Non-Application Layer Protocol (T1095), Data Encoding (T1132)
author: Marie Euler
references:
    - 'https://github.com/Neo23x0/auditd'
date: 2020/05/18
logsource:
    product: linux
    service: auditd
detection:
    selection:
        key:
            - 'susp_activity'
    condition: selection
falsepositives:
    - Admin or User activity
level: medium
tags:
    - attack.command_and_control
```
