---
title: "Publicly Accessible RDP Service"
aliases:
  - "/rule/1fc0809e-06bf-4de3-ad52-25e5263b7623"

tags:
  - attack.t1021
  - attack.t1021.001



date: Sun, 23 Aug 2020 13:16:42 -0400


---

Detects connections from routable IPs to an RDP listener - which is indicative of a publicly-accessible RDP service.

<!--more-->


## Known false-positives

* none



## References

* https://attack.mitre.org/techniques/T1021/001/


## Raw rule
```yaml
title: Publicly Accessible RDP Service
id: 1fc0809e-06bf-4de3-ad52-25e5263b7623
status: experimental
description: Detects connections from routable IPs to an RDP listener - which is indicative of a publicly-accessible RDP service.
references:
    - https://attack.mitre.org/techniques/T1021/001/
tags:
    - attack.t1021 # an old one
    - attack.t1021.001
author: 'Josh Brower @DefensiveDepth'
date: 2020/08/22 
logsource:
    product: zeek
    service: rdp
detection:
    selection:
      src_ip|startswith:
        - '192.168.'
        - '10.'
        - '172.16.'
        - '172.17.'
        - '172.18.'
        - '172.19.'
        - '172.20.'
        - '172.21.'
        - '172.22.'
        - '172.23.'
        - '172.24.'
        - '172.25.'
        - '172.26.'
        - '172.27.'
        - '172.28.'
        - '172.29.'
        - '172.30.'
        - '172.31.'
    #approved_rdp:
      #dst_ip:
        #- x.x.x.x
    condition: not selection #and not approved_rdp
fields:
    - src_ip
    - dst_ip
falsepositives:
    - none
level: high

```