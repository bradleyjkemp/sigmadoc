---
title: "Suspicious Csc.exe Source File Folder"
aliases:
  - "/rule/dcaa3f04-70c3-427a-80b4-b870d73c94c4"

tags:
  - attack.defense_evasion
  - attack.t1500



date: Sat, 24 Aug 2019 13:49:40 +0200


---

Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)

<!--more-->


## Known false-positives

* https://twitter.com/gN3mes1s/status/1206874118282448897
* https://twitter.com/gabriele_pippi/status/1206907900268072962



## References

* https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/
* https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf
* https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/
* https://twitter.com/gN3mes1s/status/1206874118282448897


## Raw rule
```yaml
title: Suspicious Csc.exe Source File Folder
id: dcaa3f04-70c3-427a-80b4-b870d73c94c4
description: Detects a suspicious execution of csc.exe, which uses a source in a suspicious folder (e.g. AppData)
status: experimental
references:
    - https://securityboulevard.com/2019/08/agent-tesla-evading-edr-by-removing-api-hooks/
    - https://www.clearskysec.com/wp-content/uploads/2018/11/MuddyWater-Operations-in-Lebanon-and-Oman.pdf
    - https://app.any.run/tasks/c6993447-d1d8-414e-b856-675325e5aa09/
    - https://twitter.com/gN3mes1s/status/1206874118282448897
author: Florian Roth
date: 2019/08/24
modified: 2020/09/05
tags:
    - attack.defense_evasion
    - attack.t1500
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: '*\csc.exe'
        CommandLine:
            - '*\AppData\\*'
            - '*\Windows\Temp\\*'
    filter:
        ParentImage:
            - 'C:\Program Files*'  # https://twitter.com/gN3mes1s/status/1206874118282448897
            - '*\sdiagnhost.exe'  # https://twitter.com/gN3mes1s/status/1206874118282448897
            - '*\w3wp.exe'  # https://twitter.com/gabriele_pippi/status/1206907900268072962
    condition: selection and not filter
falsepositives:
    - https://twitter.com/gN3mes1s/status/1206874118282448897
    - https://twitter.com/gabriele_pippi/status/1206907900268072962
level: high

```