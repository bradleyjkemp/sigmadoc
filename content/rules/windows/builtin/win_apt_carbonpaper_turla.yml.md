---
title: "Turla Service Install"
aliases:
  - "/rule/1df8b3da-b0ac-4d8a-b7c7-6cb7c24160e4"

tags:
  - attack.persistence
  - attack.g0010
  - attack.t1050
  - attack.t1543.003



date: Fri, 31 Mar 2017 19:25:41 +0200


---

This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET

<!--more-->


## Known false-positives

* Unknown



## References

* https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/


## Raw rule
```yaml
title: Turla Service Install
id: 1df8b3da-b0ac-4d8a-b7c7-6cb7c24160e4
description: This method detects a service install of malicious services mentioned in Carbon Paper - Turla report by ESET
references:
    - https://www.welivesecurity.com/2017/03/30/carbon-paper-peering-turlas-second-stage-backdoor/
tags:
    - attack.persistence
    - attack.g0010
    - attack.t1050          # an old one
    - attack.t1543.003
date: 2017/03/31
author: Florian Roth
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
        ServiceName:
            - 'srservice'
            - 'ipvpn'
            - 'hkmsvc'
    condition: selection
falsepositives:
    - Unknown
level: high

```
