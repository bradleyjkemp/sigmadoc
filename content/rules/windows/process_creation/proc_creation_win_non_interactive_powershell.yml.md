---
title: "Non Interactive PowerShell"
aliases:
  - "/rule/f4bbd493-b796-416e-bbf2-121235348529"


tags:
  - attack.execution
  - attack.t1059.001



status: experimental





date: Thu, 24 Oct 2019 15:48:38 +0200


---

Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent.

<!--more-->


## Known false-positives

* Legitimate programs executing PowerShell scripts



## References

* https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190410151110.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_non_interactive_powershell.yml))
```yaml
title: Non Interactive PowerShell
id: f4bbd493-b796-416e-bbf2-121235348529
description: Detects non-interactive PowerShell activity by looking at powershell.exe with not explorer.exe as a parent.
status: experimental
date: 2019/09/12
modified: 2021/05/10
author: Roberto Rodriguez @Cyb3rWard0g (rule), oscd.community (improvements)
references:
    - https://threathunterplaybook.com/notebooks/windows/02_execution/WIN-190410151110.html
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
    filter:
        ParentImage|endswith: 
            - '\explorer.exe'
            - '\CompatTelRunner.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate programs executing PowerShell scripts
level: low

```
