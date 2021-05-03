---
title: "Rundll32 Internet Connection"
aliases:
  - "/rule/cdc8da7d-c303-42f8-b08c-b4ab47230263"

tags:
  - attack.defense_evasion
  - attack.t1218.011
  - attack.t1085
  - attack.execution



date: Sat, 4 Nov 2017 14:44:16 +0100


---

Detects a rundll32 that communicates with public IP addresses

<!--more-->


## Known false-positives

* Communication to other corporate systems that use IP addresses from public address spaces



## References

* https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100


## Raw rule
```yaml
title: Rundll32 Internet Connection
id: cdc8da7d-c303-42f8-b08c-b4ab47230263
status: experimental
description: Detects a rundll32 that communicates with public IP addresses
references:
    - https://www.hybrid-analysis.com/sample/759fb4c0091a78c5ee035715afe3084686a8493f39014aea72dae36869de9ff6?environmentId=100
author: Florian Roth
date: 2017/11/04
modified: 2020/08/24
tags:
    - attack.defense_evasion
    - attack.t1218.011
    - attack.t1085  # an old one
    - attack.execution
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image: '*\rundll32.exe'
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
            - '127.*'
    condition: selection and not filter
falsepositives:
    - Communication to other corporate systems that use IP addresses from public address spaces
level: medium

```