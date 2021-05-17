---
title: "StoneDrill Service Install"
aliases:
  - "/rule/9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6"

tags:
  - attack.persistence
  - attack.g0064
  - attack.t1050
  - attack.t1543.003





level: high



date: Tue, 7 Mar 2017 09:24:06 +0100


---

This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky

<!--more-->


## Known false-positives

* Unlikely



## References

* https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/


## Raw rule
```yaml
title: StoneDrill Service Install
id: 9e987c6c-4c1e-40d8-bd85-dd26fba8fdd6
description: This method detects a service install of the malicious Microsoft Network Realtime Inspection Service service described in StoneDrill report by Kaspersky
author: Florian Roth
date: 2017/03/07
references:
    - https://securelist.com/blog/research/77725/from-shamoon-to-stonedrill/
tags:
    - attack.persistence
    - attack.g0064
    - attack.t1050          # an old one
    - attack.t1543.003
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName: NtsSrv
        ServiceFileName: '* LocalService'
    condition: selection
falsepositives:
    - Unlikely
level: high

```
