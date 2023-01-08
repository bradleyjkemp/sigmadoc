---
title: "Control Panel Items"
aliases:
  - "/rule/0ba863e6-def5-4e50-9cea-4dd8c7dc46a4"
ruleid: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4

tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218.002
  - attack.persistence
  - attack.t1546



status: test





date: Tue, 27 Aug 2019 14:55:55 +0630


---

Detects the malicious use of a control panel item

<!--more-->


## Known false-positives

* Unknown



## References

* https://attack.mitre.org/techniques/T1196/
* https://ired.team/offensive-security/code-execution/code-execution-through-control-panel-add-ins


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_control_panel_item.yml))
```yaml
title: Control Panel Items
id: 0ba863e6-def5-4e50-9cea-4dd8c7dc46a4
status: test
description: Detects the malicious use of a control panel item
author: Kyaw Min Thein, Furkan Caliskan (@caliskanfurkan_)
references:
  - https://attack.mitre.org/techniques/T1196/
  - https://ired.team/offensive-security/code-execution/code-execution-through-control-panel-add-ins
date: 2020/06/22
modified: 2022/01/07
logsource:
  product: windows
  category: process_creation
detection:
  selection1:
    CommandLine|endswith: '.cpl'
  filter:
    CommandLine|contains:
      - '\System32\'
      - '%System%'
  selection2:
    Image|endswith: '\reg.exe'
    CommandLine|contains: 'add'
  selection3:
    CommandLine|contains:
      - 'CurrentVersion\\Control Panel\\CPLs'
  condition: (selection1 and not filter) or (selection2 and selection3)
falsepositives:
  - Unknown
level: critical
tags:
  - attack.execution
  - attack.defense_evasion
  - attack.t1218.002
  - attack.persistence
  - attack.t1546

```
