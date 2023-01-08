---
title: "Lazarus Activity"
aliases:
  - "/rule/24c4d154-05a4-4b99-b57d-9b977472443a"
ruleid: 24c4d154-05a4-4b99-b57d-9b977472443a

tags:
  - attack.g0032
  - attack.execution
  - attack.t1059



status: experimental





date: Wed, 23 Dec 2020 14:43:32 +0100


---

Detects different process creation events as described in various threat reports on Lazarus group activity

<!--more-->


## Known false-positives

* Overlap with legitimate process activity in some cases (especially selection 3 and 4)



## References

* https://securelist.com/lazarus-covets-covid-19-related-intelligence/99906/
* https://www.hvs-consulting.de/lazarus-report/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_lazarus_activity_dec20.yml))
```yaml
title: Lazarus Activity
id: 24c4d154-05a4-4b99-b57d-9b977472443a
description: Detects different process creation events as described in various threat reports on Lazarus group activity
status: experimental
references:
    - https://securelist.com/lazarus-covets-covid-19-related-intelligence/99906/
    - https://www.hvs-consulting.de/lazarus-report/
tags:
    - attack.g0032
    - attack.execution
    - attack.t1059 
author: Florian Roth
date: 2020/12/23
modified: 2021/06/27
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains:
            - 'reg.exe save hklm\sam %temp%\~reg_sam.save'
            - '1q2w3e4r@#$@#$@#$'
            - ' -hp1q2w3e4 '
            - '.dat data03 10000 -p '
    selection2:
        CommandLine|contains|all:
            - 'process call create'
            - ' > %temp%\~'
    selection3:
        CommandLine|contains|all:
            - 'netstat -aon | find '
            - ' > %temp%\~'
    # Network share discovery
    selection4:
        CommandLine|contains:
            - '.255 10 C:\ProgramData\'
    condition: 1 of selection*
falsepositives:
    - Overlap with legitimate process activity in some cases (especially selection 3 and 4)
level: critical

```
