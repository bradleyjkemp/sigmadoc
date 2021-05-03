---
title: "Control Panel Items"
aliases:
  - "/rule/0ba863e6-def5-4e50-9cea-4dd8c7dc46a4"

tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218.002
  - attack.t1196
  - attack.persistence
  - attack.t1546



date: Tue, 27 Aug 2019 14:55:55 +0630


---

Detects the malicious use of a control panel item

<!--more-->


## Known false-positives

* Unknown




## Raw rule
```yaml
title: Control Panel Items
id: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
status: experimental
description: Detects the malicious use of a control panel item
reference:
    - https://attack.mitre.org/techniques/T1196/
    - https://ired.team/offensive-security/code-execution/code-execution-through-control-panel-add-ins
tags:
    - attack.execution
    - attack.defense_evasion
    - attack.t1218.002
    - attack.t1196  # an old one
    - attack.persistence
    - attack.t1546
author: Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)
date: 2020/06/22
modified: 2020/08/29
level: critical
logsource:
    product: windows
    category: process_creation
detection:
    selection1:
        CommandLine: '*.cpl'
    filter:
        CommandLine:
            - '*\System32\\*'
            - '*%System%*'
    selection2:
        CommandLine:
            - '*reg add*'
    selection3:
        CommandLine:
            - '*CurrentVersion\\Control Panel\\CPLs*'
    condition: (selection1 and not filter) or (selection2 and selection3)
falsepositives:
    - Unknown

```
