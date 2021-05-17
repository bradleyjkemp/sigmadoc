---
title: "Cred Dump-Tools Named Pipes"
aliases:
  - "/rule/961d0ba2-3eea-4303-a930-2cf78bbfcc5e"

tags:
  - attack.credential_access
  - attack.t1003
  - attack.t1003.001
  - attack.t1003.002
  - attack.t1003.004
  - attack.t1003.005



status: experimental



level: critical



date: Mon, 4 Nov 2019 04:26:34 +0300


---

Detects well-known credential dumping tools execution via specific named pipes

<!--more-->


## Known false-positives

* Legitimate Administrator using tool for password recovery



## References

* https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment


## Raw rule
```yaml
title: Cred Dump-Tools Named Pipes
id: 961d0ba2-3eea-4303-a930-2cf78bbfcc5e
description: Detects well-known credential dumping tools execution via specific named pipes
author: Teymur Kheirkhabarov, oscd.community
date: 2019/11/01
modified: 2020/08/28
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - attack.t1003.001
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.005
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 17
        PipeName|contains:
            - '\lsadump'
            - '\cachedump'
            - '\wceservicepipe'
    condition: selection
falsepositives:
    - Legitimate Administrator using tool for password recovery
level: critical
status: experimental

```
