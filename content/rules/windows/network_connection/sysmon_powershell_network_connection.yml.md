---
title: "PowerShell Network Connections"
aliases:
  - "/rule/1f21ec3f-810d-4b0e-8045-322202e22b4b"

tags:
  - attack.execution
  - attack.t1059.001
  - attack.t1086



date: Mon, 13 Mar 2017 13:57:41 +0100


---

Detects a Powershell process that opens network connections - check for suspicious target ports and target systems - adjust to your environment (e.g. extend filters with company's ip range')

<!--more-->


## Known false-positives

* Administrative scripts



## References

* https://www.youtube.com/watch?v=DLtJTxMWZ2o


## Raw rule
```yaml
title: PowerShell Network Connections
id: 1f21ec3f-810d-4b0e-8045-322202e22b4b
status: experimental
description: Detects a Powershell process that opens network connections - check for suspicious target ports and target systems - adjust to your environment (e.g.
    extend filters with company's ip range')
author: Florian Roth
date: 2017/03/13
references:
    - https://www.youtube.com/watch?v=DLtJTxMWZ2o
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  # an old one
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image: '*\powershell.exe'
        Initiated: 'true'
    filter:
        DestinationIp:
            - '10.*'
            - '192.168.*'
            - '172.16.*'
            - '172.17.*'
            - '172.18.*'
            - '172.19.*'
            - '172.20.*'
            - '172.21.*'
            - '172.22.*'
            - '172.23.*'
            - '172.24.*'
            - '172.25.*'
            - '172.26.*'
            - '172.27.*'
            - '172.28.*'
            - '172.29.*'
            - '172.30.*'
            - '172.31.*'
            - '127.0.0.1'
        DestinationIsIpv6: 'false'
        User: 'NT AUTHORITY\SYSTEM'
    condition: selection and not filter
falsepositives:
    - Administrative scripts
level: low

```