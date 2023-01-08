---
title: "Regsvr32 Network Activity"
aliases:
  - "/rule/c7e91a02-d771-4a6d-a700-42587e0b1095"
ruleid: c7e91a02-d771-4a6d-a700-42587e0b1095

tags:
  - attack.execution
  - attack.t1559.001
  - attack.defense_evasion
  - attack.t1218.010



status: experimental





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


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/network_connection/net_connection_win_regsvr32_network_activity.yml))
```yaml
title: Regsvr32 Network Activity
id: c7e91a02-d771-4a6d-a700-42587e0b1095
description: Detects network connections and DNS queries initiated by Regsvr32.exe
references:
    - https://pentestlab.blog/2017/05/11/applocker-bypass-regsvr32/
    - https://oddvar.moe/2017/12/13/applocker-case-study-how-insecure-is-it-really-part-1/
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1117/T1117.md
author: Dmitriy Lifanov, oscd.community
status: experimental
date: 2019/10/25
modified: 2021/09/21
logsource:
    category: network_connection
    product: windows
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
tags:
    - attack.execution
    - attack.t1559.001
    - attack.defense_evasion
    - attack.t1218.010
```
