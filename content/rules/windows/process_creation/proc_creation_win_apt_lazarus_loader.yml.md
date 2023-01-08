---
title: "Lazarus Loaders"
aliases:
  - "/rule/7b49c990-4a9a-4e65-ba95-47c9cc448f6e"
ruleid: 7b49c990-4a9a-4e65-ba95-47c9cc448f6e

tags:
  - attack.g0032
  - attack.execution
  - attack.t1059



status: test





date: Wed, 23 Dec 2020 13:25:16 +0100


---

Detects different loaders as described in various threat reports on Lazarus group activity

<!--more-->


## Known false-positives

* unknown



## References

* https://www.hvs-consulting.de/lazarus-report/
* https://securelist.com/lazarus-covets-covid-19-related-intelligence/99906/


## Raw rule ([edit](https://github.com/SigmaHQ/sigma/edit/master/rules/windows/process_creation/proc_creation_win_apt_lazarus_loader.yml))
```yaml
title: Lazarus Loaders
id: 7b49c990-4a9a-4e65-ba95-47c9cc448f6e
description: Detects different loaders as described in various threat reports on Lazarus group activity
status: test
references:
    - https://www.hvs-consulting.de/lazarus-report/
    - https://securelist.com/lazarus-covets-covid-19-related-intelligence/99906/
tags:
    - attack.g0032
    - attack.execution
    - attack.t1059 
author: Florian Roth, wagga
date: 2020/12/23
modified: 2021/06/27
logsource:
    category: process_creation
    product: windows
detection:
    selection_cmd1:
        CommandLine|contains|all: 
            - 'cmd.exe /c '
            - ' -p 0x'
    selection_cmd2:
        CommandLine|contains:
            - 'C:\ProgramData\'
            - 'C:\RECYCLER\'
    selection_rundll1:
        CommandLine|contains|all: 
            - 'rundll32.exe '
            - 'C:\ProgramData\'
    selection_rundll2:
        CommandLine|contains:
            - '.bin,'
            - '.tmp,'
            - '.dat,'
            - '.io,'
            - '.ini,'
            - '.db,'
    condition: ( selection_cmd1 and selection_cmd2 ) or ( selection_rundll1 and selection_rundll2 )
falsepositives:
    - unknown
level: critical

```
