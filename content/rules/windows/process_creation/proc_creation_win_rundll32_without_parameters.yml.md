---
title: "Rundll32 Without Parameters"
aliases:
  - "/rule/5bb68627-3198-40ca-b458-49f973db8752"
ruleid: 5bb68627-3198-40ca-b458-49f973db8752

tags:
  - attack.lateral_movement
  - attack.t1021.002
  - attack.t1570
  - attack.execution
  - attack.t1569.002



status: experimental





date: Thu, 1 Jul 2021 12:18:30 +0545


---

Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module

<!--more-->


## Known false-positives

* Unknown



## References

* https://bczyz1.github.io/2021/01/30/psexec.html


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_rundll32_without_parameters.yml))
```yaml
title: Rundll32 Without Parameters
id: 5bb68627-3198-40ca-b458-49f973db8752
status: experimental
description: Detects rundll32 execution without parameters as observed when running Metasploit windows/smb/psexec exploit module
author: Bartlomiej Czyz, Relativity
date: 2021/01/31
references:
    - https://bczyz1.github.io/2021/01/30/psexec.html
tags:
    - attack.lateral_movement
    - attack.t1021.002
    - attack.t1570
    - attack.execution
    - attack.t1569.002
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: 'rundll32.exe'
    condition: selection
fields:
    - ComputerName
    - SubjectUserName
    - CommandLine
    - Image
    - ParentImage
falsepositives:
    - Unknown
level: high

```
