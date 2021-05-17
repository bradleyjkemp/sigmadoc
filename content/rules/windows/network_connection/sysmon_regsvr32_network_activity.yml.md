---
title: "Regsvr32 Network Activity"
aliases:
  - "/rule/c7e91a02-d771-4a6d-a700-42587e0b1095"

tags:
  - attack.execution
  - attack.t1559.001
  - attack.t1175
  - attack.defense_evasion
  - attack.t1218.010
  - attack.t1117



status: experimental



level: high



date: Fri, 25 Oct 2019 17:57:56 +0300


---

Detects network connections and DNS queries initiated by Regsvr32.exe

<!--more-->


## Known false-positives

* unknown



## References

* https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/
* https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
* https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md


## Raw rule
```yaml
action: global
title: Regsvr32 Network Activity
id: c7e91a02-d771-4a6d-a700-42587e0b1095
description: Detects network connections and DNS queries initiated by Regsvr32.exe
references:
    - https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/
    - https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md
tags:
    - attack.execution
    - attack.t1559.001
    - attack.t1175  # an old one
    - attack.defense_evasion
    - attack.t1218.010
    - attack.t1117  # an old one
author: Dmitriy Lifanov, oscd.community
status: experimental
date: 2019/10/25
modified: 2020/08/24
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
    condition: selection
fields:
    - ComputerName
    - User
    - Image
    - DestinationIp
    - DestinationPort
falsepositives:
    - unknown
level: high
---
logsource:
    category: network_connection
    product: windows
---
logsource:
    category: dns_query
    product: windows

```
